using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace proxyServer
{
    interface IService
    {
        bool Started { get; set; }
        bool SelfInteractive { get; set; }
        string PRestore { get; set; }
        void WarningMessage();
    }
}
