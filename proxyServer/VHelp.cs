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
    public class VHelp : IDisposable
    {
        //IDisposable Implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                Array.Clear(services, 0, services.Length);
                services = null;
                iGuide.Clear();
                iGuide = null;
                exp.Clear();
                exp = null;
                currentHelp = null;
                ctx = null;
                console = null;
            }

            disposed = true;
        }

        object[] services;
        Dictionary<string, InteractiveHelp> iGuide = new Dictionary<string, InteractiveHelp>();
        List<string> exp = new List<string>();
        public bool GetCommandUpdates = false;
        private string currentHelp = "";
        private int currentHelpIndex = 0;
        private Form1 ctx;
        private VConsole console;

        public enum Type
        {
            ParameterList,
            Command,
        }

        public enum InteractiveLevel
        {
            Normal,
            Listing,
            EasyToComplete
        }

        public struct InteractiveHelp
        {
            public List<string> messages;
            public List<int> idle;
            public List<Func<bool>> triggerNext;
            public InteractiveLevel level;
        }

        public VHelp(Form1 context, VConsole con)
        {
            ctx = context;
            console = con;
        }

        /// <summary>
        /// List all commands belonging to a specified object
        /// </summary>
        /// <param name="input">Object, that can be converted to an IHelp object</param>

        public void ListAll(object input)
        {
            IHelp ihObject = (IHelp)input;
            if (!File.Exists(ihObject.HelpFile)) return;

            using (System.Xml.XmlReader xml = System.Xml.XmlReader.Create(ihObject.HelpFile))
            {
                while (xml.Read())
                {
                    if (xml.IsEmptyElement) continue;

                    if (xml.IsStartElement())
                    {
                        string element = xml.Name;
                        if (element.StartsWith("cmd_"))
                        {
                            string command = element.Substring(4);
                            command = command.Replace(".", " ");
                            xml.Read();
                            string exp = xml.Value;
                            console.Write(command + " - " + exp + "\r\n");
                        }
                    }
                }
            }

            console.WriteLine("For more detailed help type: help [command_name], to read the required parameters!");
        }

        /// <summary>
        /// Load the services into the local service list
        /// </summary>
        /// <param name="service">The service object itself</param>

        public void RegisterServices(params object[] service)
        {
            services = service;
        }

        /// <summary>
        /// Run the help mode based on the command on the needed service
        /// </summary>
        /// <param name="command">The current command</param>
        /// <param name="helpType">The type of the help to run</param>
        /// <param name="overloadAuto">Overload the automatic IHelp object</param>

        public void GetHelp(string command, Type helpType, object overloadAuto = null)
        {
            IHelp help;
            if (overloadAuto == null) help = GetHelperClass(command);
            else help = (IHelp)overloadAuto;
            if (help == null) return;

            if (command.StartsWith("help ")) command = command.Substring(5);

            using (System.Xml.XmlReader r = System.Xml.XmlReader.Create(help.HelpFile))
            {
                int cmdNumber = 1;

                while (r.Read())
                {
                    if (r.IsEmptyElement) continue;

                    if (r.IsStartElement())
                    {
                        string eName = r.Name;
                        if (eName == "help" || eName == "commands") continue;
                        if (eName.StartsWith("cmd_") && helpType == Type.Command)
                        {
                            string cmd = r.Name.Substring(4);
                            cmd = cmd.Replace(".", " ");
                            string chk = cmd.ToLower();
                            if (!command.ToLower().StartsWith(chk)) continue;
                            string explenation = "";
                            string[] parameters;
                            parameters = r.GetAttribute("params").Split(',');
                            r.Read();
                            explenation = r.Value;
                            if (cmdNumber == 1) console.Write("\r\n");
                            console.Write(cmdNumber.ToString() + ": " + cmd + " ");
                            int index = 0;
                            foreach (string p in parameters)
                            {
                                if (p == "") continue;
                                console.Write("[" + p + "]");
                                if (index < parameters.Length) console.Write(" ");
                                index++;
                            }

                            console.Write("\r\n" + explenation + "\r\n");
                            cmdNumber++;
                        }

                        if (eName.StartsWith("p_") && helpType == Type.ParameterList)
                        {
                            string pName = eName.Substring(2);
                            pName = pName.Replace(".", " ");
                            string chk = pName.ToLower();
                            if (!command.ToLower().StartsWith(chk)) continue;
                            string[] validValues = r.GetAttribute("values").Split(',');
                            r.Read();
                            string explanation = r.Value;

                            if (cmdNumber == 1) console.Write("\r\n");

                            console.Write(cmdNumber.ToString() + ": " + pName + "\r\n");

                            foreach (string v in validValues)
                            {
                                if (v == "|")
                                {
                                    console.Write("\r\n");
                                    continue;
                                }
                                console.Write(v + ",");
                            }

                            console.Write("\r\n" + explanation + "\r\n");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Create a group for interactive help running the user through the process of a command, action
        /// </summary>
        /// <param name="group">The grouping name for the guide</param>
        /// <param name="level">The help level of the guide</param>

        public void CreateInteractive(string group, string explanation, InteractiveLevel level = InteractiveLevel.Normal)
        {
            if (iGuide.ContainsKey(group)) return;
            InteractiveHelp ih = new InteractiveHelp
            {
                level = level,
                messages = new List<string>(),
                idle = new List<int>(),
                triggerNext = new List<Func<bool>>()
            };
            iGuide.Add(group, ih);
            exp.Add(explanation);
        }

        /// <summary>
        /// Add one or multiple message/step to a guide
        /// </summary>
        /// <param name="group">The name of the earlier created group</param>
        /// <param name="messages">One or more string message/step</param>

        public void AddMessage(string group, params string[] messages)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<string> f = new List<string>();

            foreach (string msg in ih.messages)
            {
                f.Add(msg);
            }

            foreach (string msg in messages)
            {
                f.Add(msg);
            }

            ih.messages = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Add idle time between messages
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="times">The idle time in seconds</param>

        public void AddIdle(string group, params int[] times)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<int> f = new List<int>();

            foreach (int time in ih.idle)
            {
                f.Add(time);
            }

            foreach (int time in times)
            {
                f.Add(time);
            }

            ih.idle = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Add when to move to the next message/step
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="triggers">A condition, which is when true the next step come's</param>

        public void AddTrigger(string group, params Func<bool>[] triggers)
        {
            if (!iGuide.ContainsKey(group)) return;

            InteractiveHelp ih = iGuide[group];
            List<Func<bool>> f = new List<Func<bool>>();

            foreach (Func<bool> condition in ih.triggerNext)
            {
                f.Add(condition);
            }

            foreach (Func<bool> condition in triggers)
            {
                f.Add(condition);
            }

            ih.triggerNext = f;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Remove all messages from a group
        /// </summary>
        /// <param name="group">The name of the group</param>

        public void ClearMessage(string group)
        {
            if (!iGuide.ContainsKey(group)) return;
            iGuide[group].messages.Clear();
        }

        /// <summary>
        /// Set the level of tutorial for a group
        /// </summary>
        /// <param name="group">The group name</param>
        /// <param name="level">The desired level</param>

        public void SetLevel(string group, InteractiveLevel level)
        {
            if (!iGuide.ContainsKey(group)) return;
            InteractiveHelp ih = iGuide[group];
            ih.level = level;
            iGuide[group] = ih;
        }

        /// <summary>
        /// Execute's a configured guide based on the parameters
        /// </summary>
        /// <param name="group">The name of the group to execute</param>

        public void RunInteractiveHelp(string group)
        {
            if (!iGuide.ContainsKey(group)) return;
            bool countCheck = false;
            int msgCount = iGuide[group].messages.Count;
            int idleCount = iGuide[group].idle.Count;
            int triggerCount = iGuide[group].messages.Count;
            if (msgCount == idleCount && msgCount == triggerCount) countCheck = true;
            if (!countCheck) return;
            InteractiveLevel level = iGuide[group].level;
            string[] messages = iGuide[group].messages.ToArray();
            GetCommandUpdates = true;
            Thread.Sleep(iGuide[group].idle[0] * 1000);
            WriteLine(messages[currentHelpIndex]);
            currentHelpIndex++;
            currentHelp = group;
        }

        /// <summary>
        /// Callback for checking progress of  the walkthrough
        /// </summary>
        /// <param name="cmd">String command</param>

        public void OnCommand(string cmd)
        {
            InteractiveHelp ih = iGuide[currentHelp];
            int currentIdle = ih.idle[currentHelpIndex - 1];
            Func<bool> currentCondition = ih.triggerNext[currentHelpIndex - 1];
            if (currentHelpIndex >= ih.messages.Count)
            {
                Thread.Sleep(currentIdle * 1000);
                WriteLine("Tutorial completed!");
                GetCommandUpdates = false;
                currentHelp = "";
                currentHelpIndex = 0;
                return;
            }
            string currentMessage = ih.messages[currentHelpIndex];

            if (currentCondition())
            {
                Thread.Sleep(currentIdle * 1000);
                WriteLine(currentMessage);
                currentHelpIndex++;
            }
        }

        /// <summary>
        /// List the Interactive Guide Modules
        /// </summary>

        public void ListInteractive()
        {
            if (iGuide.Count == 0)
            {
                console.WriteLine("No interactive help modules available!");
                return;
            }

            int index = 0;

            foreach (string name in iGuide.Keys)
            {
                console.WriteLine(name + " - " + exp[index]);
                index++;
            }
        }

        private IHelp GetHelperClass(string cmd)
        {
            if (cmd.StartsWith("help ")) cmd = cmd.Substring(5);

            foreach (object o in services)
            {
                IHelp obj;
                try { obj = (IHelp)o; }
                catch (Exception) { continue; };

                if (!File.Exists(obj.HelpFile)) continue;
                string firstLine = File.ReadAllLines(obj.HelpFile)[1];
                firstLine = firstLine.Replace("</commands>", String.Empty);
                firstLine = firstLine.Replace("<commands>", String.Empty);
                if (!firstLine.Contains(","))
                {
                    if (firstLine == cmd) return obj;
                    else continue;
                }
                string[] cmds = firstLine.Split(',');
                foreach (string entry in cmds)
                {
                    if (cmd.StartsWith(entry) && entry != "")
                    {
                        return obj;
                    }
                }
            }

            return null;
        }

        private void WriteLine(string message)
        {
            console.Clear();
            console.WriteLine(message, console.GetIntercativeGroup());
        }
    }

}
