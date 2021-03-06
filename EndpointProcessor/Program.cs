using System.ServiceProcess;

namespace EndpointProcessor
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new EndpointProcessor()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
