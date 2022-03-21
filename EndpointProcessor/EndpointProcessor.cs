using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Timers;
using System.Xml;

namespace EndpointProcessor
{
    public partial class EndpointProcessor : ServiceBase
    {
        private string endpoint_directory = @"C:\\BkavEnterprise\\ReportPy\\BkavReportProcessor_Endpoint\\report_to_soc\\";
        private string event_log_directory = @"C:\\EndpointProcessor\\EventLog\\";
        private string service_log_directory = @"C:\\EndpointProcessor\\ServiceLog\\";
        private int rotate_time = 604800;   //  7 days
        private FileSystemWatcher fsw;
        public EndpointProcessor()
        {
            InitializeComponent();
        }
        private int to_unix_timeseconds(DateTime date)
        {
            DateTime point = new DateTime(1970, 1, 1);
            TimeSpan time = date.Subtract(point);
            return (int)time.TotalSeconds;
        }
        private void OnTimer(object sender, ElapsedEventArgs e)
        {
            List<string> directorys = new List<string>();
            directorys.Add(event_log_directory);
            directorys.Add(service_log_directory);
            int now = to_unix_timeseconds(DateTime.Now);

            foreach (string directory in directorys)
            {
                // Process the list of files found in the directory.
                string[] file_entries = Directory.GetFiles(directory);
                foreach (string file_path in file_entries)
                {
                    int file_creation_time = to_unix_timeseconds(File.GetCreationTime(file_path));
                    if ((now - file_creation_time) > rotate_time)
                    {
                        delete_file(file_path);
                        string message = String.Format("Delete file by logrotate: {0}", file_path);
                        report_generation("INFO", message);
                    }
                }
            }
        }
        protected override void OnStart(string[] args)
        {
            //  Create Directory if it doesn't exist.
            if (!Directory.Exists(event_log_directory))
                System.IO.Directory.CreateDirectory(event_log_directory);
            if (!Directory.Exists(service_log_directory))
                System.IO.Directory.CreateDirectory(service_log_directory);

            // Set up a timer that triggers every minute.
            System.Timers.Timer timer = new System.Timers.Timer();
            timer.Interval = 60000; // 60 seconds

            //  Call function OnTimer() when the interval elapses.
            timer.Elapsed += new ElapsedEventHandler(this.OnTimer);
            timer.Start();

            //  Start processor
            filesystemwatcher();
            report_generation("INFO", "Service started");
        }
        private void filesystemwatcher()
        {
            //  Create a FileSystemWatcher to monitor all files in folder.
            fsw = new FileSystemWatcher(endpoint_directory);

            //  Register a handler that gets called when a file is created
            fsw.Created += new FileSystemEventHandler(OnChanged);

            //  Register a handler that gets called if the
            //  FileSystemWatcher needs to report an error.
            fsw.Error += new ErrorEventHandler(OnError);

            // Monitor only xml files.
            fsw.Filter = "*.xml";

            //  Unsupervised subdirectories
            fsw.IncludeSubdirectories = false;

            //  Sets the size (in bytes) of the internal buffer to 64KB (maximum).
            fsw.InternalBufferSize = 65536;

            //  Begin watching.
            fsw.EnableRaisingEvents = true;
            report_generation("INFO", "Begin watching");
        }
        private void OnChanged(object source, FileSystemEventArgs e)
        {
            //  Show that a file has been created.
            //WatcherChangeTypes wct = e.ChangeType;

            file_parsing(e.FullPath);
        }
        private void OnError(object source, ErrorEventArgs e)
        {
            //  Show that an error has been detected.
            report_generation("ERROR", "The FileSystemWatcher has detected an error");

            //  Give more information if the error is due to an internal buffer overflow.
            if (e.GetException().GetType() == typeof(InternalBufferOverflowException))
            {
                //  This can happen if Windows is reporting many file system events quickly
                //  and internal buffer of the  FileSystemWatcher is not large enough to handle this
                //  rate of events. The InternalBufferOverflowException error informs the application
                //  that some of the file system events are being lost.
                report_generation("ERROR", ("The file system watcher experienced an internal buffer overflow: " + e.GetException().Message));
            }
        }
        private void file_parsing(string file_path)
        {
            int count = 0;
            int process_status = 0;

        process_start:
            //  Loads XML from a file.
            XmlDocument doc = load_xml(file_path);

            //  Parsing
            if (doc != null)
            {
                //  Get elements of XML file.
                Dictionary<string, XmlNodeList> elements = get_elements(doc);

                //  Get timestamp
                string timestamp = elements["datetime"][0].InnerText;

                //  Get organizatin info
                XmlNodeList header = doc.GetElementsByTagName("edXML:From")[0].ChildNodes;
                string org_info = @"";
                foreach (XmlNode org in header)
                {
                    org_info += org.Name + ":" + org.InnerText + ",";
                }

                //  Get event file path.
                string event_log_file = file_path_generation(event_log_directory);

                //  Write event to log file.
                connection_to_event(timestamp, org_info, elements["connection"], event_log_file);
                malware_to_event(timestamp, org_info, elements["malware"], event_log_file);
                os_to_event(timestamp, org_info, elements["os"], event_log_file);
                qualityfeature_to_event(timestamp, org_info, elements["qualityfeature"], event_log_file);
                update_to_event(timestamp, org_info, elements["update"], event_log_file);
                vulnerability_to_event(timestamp, org_info, elements["vulnerability"], event_log_file);

                //  Set process status to success
                process_status = 0;

                //  Delete file when parsing successful.
                delete_file(file_path);
            }
            else
            {
                //  Set process status to failure
                process_status = 1;

                if (count < 1)
                {
                    //  Write error.
                    string message = String.Format("The file could not be loaded. Reload it again: {0}", file_path);
                    report_generation("ERROR", message);

                    //  increase the counter variable and reload the file.
                    count++;
                    goto process_start;
                }
            }
            if (process_status == 0 && count == 1)
                report_generation("INFO", "Reparsing successful: " + file_path);
            if (process_status == 1)
            {
                string message = String.Format("File reload failed: {0}", file_path);
                report_generation("ERROR", message);
            }
        }
        private XmlDocument load_xml(string file_path)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = false;
            try { doc.Load(file_path); }
            catch (Exception) { return null; }
            return doc;
        }
        private Dictionary<string, XmlNodeList> get_elements(XmlDocument doc)
        {
            Dictionary<string, XmlNodeList> elements = new Dictionary<string, XmlNodeList>();
            elements.Add("connection", doc.GetElementsByTagName("Connection"));
            elements.Add("datetime", doc.GetElementsByTagName("Datetime"));
            elements.Add("malware", doc.GetElementsByTagName("Malware"));
            elements.Add("os", doc.GetElementsByTagName("OS"));
            elements.Add("qualityfeature", doc.GetElementsByTagName("QualityFeature"));
            elements.Add("update", doc.GetElementsByTagName("Update"));
            elements.Add("vulnerability", doc.GetElementsByTagName("Vulnerability"));
            return elements;
        }
        private void connection_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList connections = nodes[0].ChildNodes;
            foreach (XmlNode connection in connections)
            {
                foreach (XmlNode connection_info in connection.ChildNodes)
                {
                    Dictionary<string, string> event_info = new Dictionary<string, string>();
                    string message = "@timestamp" + ":" + timestamp + ",";
                    message += org_info;
                    message += "category" + ":" + "connection" + ",";
                    //  Get machine infor
                    for (int i = 0; i < connection.Attributes.Count; i++)
                    {
                        event_info.Add(connection.Attributes[i].Name, connection.Attributes[i].Value);
                    }

                    //  Get connection infor
                    for (int i = 0; i < connection_info.ChildNodes.Count; i++)
                    {
                        event_info.Add(connection_info.ChildNodes[i].Name, connection_info.ChildNodes[i].InnerText);
                    }

                    //  Generation message
                    for (int i = 0; i < event_info.Count; i++)
                    {
                        message += event_info.ElementAt(i).Key + ":" + event_info.ElementAt(i).Value;
                        if (i < (event_info.Count - 1))
                            message += ",";
                    }
                    write_to_file(message, event_log_file);
                }
            }
        }
        private void malware_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList malwares = nodes[0].ChildNodes;
            foreach (XmlNode malware in malwares)
            {
                foreach (XmlNode malware_info in malware.ChildNodes)
                {
                    Dictionary<string, string> event_info = new Dictionary<string, string>();
                    string message = "@timestamp" + ":" + timestamp + ",";
                    message += org_info;
                    message += "category" + ":" + "malware" + ",";

                    //  Get machine infor
                    for (int i = 0; i < malware.Attributes.Count; i++)
                    {
                        event_info.Add(malware.Attributes[i].Name, malware.Attributes[i].Value);
                    }

                    //  Get malware infor
                    for (int i = 0; i < malware_info.ChildNodes.Count; i++)
                    {
                        event_info.Add(malware_info.ChildNodes[i].Name, malware_info.ChildNodes[i].InnerText);
                    }

                    //  Generation message
                    for (int i = 0; i < event_info.Count; i++)
                    {
                        message += event_info.ElementAt(i).Key + ":" + event_info.ElementAt(i).Value;
                        if (i < (event_info.Count - 1))
                            message += ",";
                    }
                    write_to_file(message, event_log_file);
                }
            }
        }
        private void os_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList oss = nodes[0].ChildNodes;
            foreach (XmlNode os in oss)
            {
                Dictionary<string, string> event_info = new Dictionary<string, string>();
                string message = "@timestamp" + ":" + timestamp + ",";
                message += org_info;
                message += "category" + ":" + "os" + ",";

                //  Get machine infor
                for (int i = 0; i < os.Attributes.Count; i++)
                {
                    event_info.Add(os.Attributes[i].Name, os.Attributes[i].Value);
                }

                //  Get os infor
                for (int i = 0; i < os.ChildNodes.Count; i++)
                {
                    event_info.Add(os.ChildNodes[i].Name, os.ChildNodes[i].InnerText);
                }

                //  Generation message
                for (int i = 0; i < event_info.Count; i++)
                {
                    message += event_info.ElementAt(i).Key + ":" + event_info.ElementAt(i).Value;
                    if (i < (event_info.Count - 1))
                        message += ",";
                }
                write_to_file(message, event_log_file);
            }
        }
        private void qualityfeature_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList qualityfeatures = nodes[0].ChildNodes;
            foreach (XmlNode qualityfeature in qualityfeatures)
            {
                Dictionary<string, string> event_info = new Dictionary<string, string>();
                string message = "@timestamp" + ":" + timestamp + ",";
                message += org_info;
                message += "category" + ":" + "qualityfeature" + ",";

                //  Get machine infor
                for (int i = 0; i < qualityfeature.Attributes.Count; i++)
                {
                    event_info.Add(qualityfeature.Attributes[i].Name, qualityfeature.Attributes[i].Value);
                }

                //  Get qualityfeature infor
                for (int i = 0; i < qualityfeature.ChildNodes.Count; i++)
                {
                    event_info.Add(qualityfeature.ChildNodes[i].Name, qualityfeature.ChildNodes[i].InnerText);
                }

                //  Generation message
                for (int i = 0; i < event_info.Count; i++)
                {
                    message += event_info.ElementAt(i).Key + ":" + event_info.ElementAt(i).Value;
                    if (i < (event_info.Count - 1))
                        message += ",";
                }
                write_to_file(message, event_log_file);
            }
        }
        private void update_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList updates = nodes[0].ChildNodes;
            foreach (XmlNode update in updates)
            {
                string message = "@timestamp" + ":" + timestamp + ",";
                message += org_info;
                message += "category" + ":" + "update" + ",";
                message += update.Name + ":" + update.InnerText;
                write_to_file(message, event_log_file);
            }
        }
        private void vulnerability_to_event(string timestamp, string org_info, XmlNodeList nodes, string event_log_file)
        {
            XmlNodeList vulnerabilitys = nodes[0].ChildNodes;
            foreach (XmlNode vulnerability in vulnerabilitys)
            {
                foreach (XmlNode vulnerability_info in vulnerability.ChildNodes)
                {
                    Dictionary<string, string> event_info = new Dictionary<string, string>();
                    string message = "@timestamp" + ":" + timestamp + ",";
                    message += org_info;
                    message += "category" + ":" + "vulnerability" + ",";

                    //  Get machine infor
                    for (int i = 0; i < vulnerability.Attributes.Count; i++)
                    {
                        event_info.Add(vulnerability.Attributes[i].Name, vulnerability.Attributes[i].Value);
                    }

                    //  Get vulnerability infor
                    for (int i = 0; i < vulnerability_info.ChildNodes.Count; i++)
                    {
                        event_info.Add(vulnerability_info.ChildNodes[i].Name, vulnerability_info.ChildNodes[i].InnerText);
                    }

                    //  Generation message
                    for (int i = 0; i < event_info.Count; i++)
                    {
                        message += event_info.ElementAt(i).Key + ":" + event_info.ElementAt(i).Value;
                        if (i < (event_info.Count - 1))
                            message += ",";
                    }
                    write_to_file(message, event_log_file);
                }
            }
        }
        private void report_generation(string level, string content)
        {
            string file_path = file_path_generation(service_log_directory);
            string message = String.Format("[{0}] [{1}] {2} ", DateTime.Now.ToString("yyyy-MM-dd-HH:mm:ss"), level, content);
            write_to_file(message, file_path);
        }
        private void write_to_file(string content, string file_path)
        {
            using (StreamWriter sw = File.AppendText(file_path))
            {
                sw.WriteLine(content.ToLower());
                sw.Close();
            }
        }
        private void delete_file(string file_path)
        {
            try { File.Delete(file_path); }
            catch (IOException exp) { report_generation("ERROR", "File deletion failed: " + exp.Message); }
        }
        private string file_path_generation(string directory)
        {
            string file_name = String.Concat(DateTime.Now.ToString("yyyy-MM-dd"), ".log");
            return String.Concat(directory, file_name);
        }
        protected override void OnStop()
        {
            //  Finish watching.
            fsw.EnableRaisingEvents = false;
            report_generation("INFO", "Service stopped");
        }
    }
}
