using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace proxyServer
{
    interface IFilter
    {
        Dictionary<string, object> FilterName { get; set; }
        VFilter Manager { get; set; }
        bool BindFilter(string filterName, object value);
        bool UnBindFilter(string filterName);
        bool SearchFilter(string sMethod, object sparam, string input);
        void BindList();
        void SetManager(VFilter manager);
        string PushBindInfo();
        void PullBindInfo(string bInfo);

    }
}
