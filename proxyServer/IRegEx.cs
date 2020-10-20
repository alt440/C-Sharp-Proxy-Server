using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace proxyServer
{
    interface IRegEx
    {
        Dictionary<string, object> RegExName { get; set; }
        VRegEx Rxmanager { get; set; }
        bool BindRegEx(string filterName, object value);
        bool UnBindRegEx(string filterName);
        bool MatchRegex(string sMethod, object parameter, string input);
        void BindListR();
        void SetManager(VRegEx manager);
        string PushRBindInfo();
        void PullRBindInfo(string bInfo);
    }
}
