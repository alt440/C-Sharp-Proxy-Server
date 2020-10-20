using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace proxyServer
{
    interface ISettings
    {
        void LoadSettings(KeyValuePair<string, string> k);
        void WriteSettings(System.Xml.XmlWriter xml);
    }
}
