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
    public class VConsole : IDisposable, ISettings
    {
        //ISettings implementation

        public void LoadSettings(KeyValuePair<string, string> kvp)
        {
            string key = kvp.Key.ToLower();
            string value = kvp.Value.ToLower();

            if (key == "fgColor") SetForeground(ctx.S2c(value));
            if (key == "bgColor") SetBackground(ctx.S2c(value));
            if (key == "font_size") SetTextSize(float.Parse(value));
        }

        public void WriteSettings(System.Xml.XmlWriter xml)
        {
            xml.WriteStartElement("settings_start");
            xml.WriteElementString("fgColor", ctx.C2s(fg));
            xml.WriteElementString("bgColor", ctx.C2s(bg));
            xml.WriteElementString("font_size", Convert.ToString(GetTextSize()));
            xml.WriteEndElement();
        }

        //IDisposable implementation

        bool disposed = false;
        SafeFileHandle handle = new SafeFileHandle(IntPtr.Zero, true);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (ctx.InvokeRequired)
            {
                BoolDelegate c = new BoolDelegate(Dispose);
                ctx.Invoke(c, new object[] { disposing });
                return;
            }

            if (disposed) return;
            if (disposing)
            {
                handle.Dispose();
                bg = System.Drawing.Color.Empty;
                fg = System.Drawing.Color.Empty;
                ctx = null;
                input.Dispose();
                output.Dispose();
                input = null;
                output = null;
                prefix = null;
                tempText = null;
                defaultXDifference = 0;
                defaultYDifference = 0;
                outputBuffer = null;
                hidden.Dispose();
                hidden = null;
                history.Clear();
                hIndex = 0;
            }

            disposed = true;
        }

        private delegate void VoidDelegate();
        private delegate void StrDelegate(string text);
        private delegate void DoubleStrDelegate(string t1, string t2);
        private delegate void BoolDelegate(bool value);
        private delegate void ColorDelegate(System.Drawing.Color color);
        private delegate void FloatDelegate(float value);
        private delegate void FontDelegate(System.Drawing.Font font);
        private delegate void BindDelegate(TextBox t1, TextBox t2);
        private delegate void SyncDelegate(int x, int y, bool overwrite);
        private delegate float ReturnFloatDelegate();
        private delegate System.Drawing.Color ReturnColorDelegate();
        private delegate string ReturnStringDelegate();

        public enum SyncMode : int
        {
            noSync = 1,
            syncWindow = 2,
            syncIO = 3
        }

        public class ReadLineEventArgs : EventArgs
        {
            private string text;

            public ReadLineEventArgs(string msg)
            {
                text = msg;
            }

            public string Text
            {
                get
                {
                    return text;
                }
            }
        }

        public delegate void ReadLineEventHandler(object obj, ReadLineEventArgs args);

        public event ReadLineEventHandler OnReadLine;

        System.Drawing.Color bg;
        System.Drawing.Color fg;
        Form1 ctx;
        TextBox input;
        TextBox output;
        string prefix = "";
        string tempText = "";
        SyncMode sync = SyncMode.noSync;
        int defaultXDifference;
        int defaultYDifference;
        bool supressEvent = false;
        bool freezWrite = false;
        string outputBuffer = "";
        bool choiceMode = false;
        bool ignoreNext = false;
        bool hideNext = false;
        bool historyNext = false;
        TextBox hidden = new TextBox();
        List<string> history = new List<string>();
        int hIndex = -1;
        public bool isDebug = false;
        private string ActiveIG = "ig.null";
        public string prevCommand = "";

        public VConsole(Form1 context, SyncMode syncSize)
        {
            ctx = context;
            sync = syncSize;
        }

        public void SyncUI(int growthX, int growthY, bool allowDefaultModify = true)
        {
            if (ctx.InvokeRequired)
            {
                SyncDelegate c = new SyncDelegate(SyncUI);
                ctx.Invoke(c, new object[] { growthX, growthY, allowDefaultModify });
                return;
            }

            if (sync == SyncMode.syncIO)
            {
                if (growthX != 0) input.Size = new System.Drawing.Size(input.Size.Width + growthX, input.Size.Height);
                output.Size = new System.Drawing.Size(output.Size.Width + growthX, output.Size.Height + growthY);
                input.Location = new System.Drawing.Point(input.Location.X, output.Size.Height + 1);
                if (allowDefaultModify)
                {
                    defaultXDifference = ctx.Size.Width - output.Size.Width;
                    defaultYDifference = ctx.Size.Height - output.Size.Height;
                }
            }

            if (sync == SyncMode.syncWindow)
            {
                ctx.Size = new System.Drawing.Size(ctx.Size.Width + growthX, ctx.Size.Height + growthY + 4);
                if (allowDefaultModify)
                {
                    defaultXDifference = input.Size.Width - ctx.Size.Width;
                    defaultYDifference = input.Size.Height - ctx.Size.Height;
                }
            }
        }

        public void Bind(TextBox inputBox, TextBox outputBox)
        {
            if (ctx.InvokeRequired)
            {
                BindDelegate c = new BindDelegate(Bind);
                ctx.Invoke(c, new object[] { inputBox, outputBox });
                return;
            }
            input = inputBox;
            output = outputBox;
        }

        public void SetFont(System.Drawing.Font font)
        {
            if (ctx.InvokeRequired)
            {
                FontDelegate c = new FontDelegate(SetFont);
                ctx.Invoke(c, new object[] { font });
                return;
            }
            supressEvent = true;
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;

            input.Font = font;
            output.Font = font;

            System.Drawing.Size nSize = TextRenderer.MeasureText("T", font);
            input.Size = new System.Drawing.Size(input.Size.Width, nSize.Height + 4); //+4 for the cursor to display
            if (sync != SyncMode.syncWindow)
            {
                SyncMode backup = sync;
                sync = SyncMode.syncWindow;
                SyncUI(nSize.Width - inputX, nSize.Height - inputY, false);
                sync = backup;
            }
            supressEvent = false;
        }

        public void SetTextSize(float textSize)
        {
            if (ctx.InvokeRequired)
            {
                FloatDelegate c = new FloatDelegate(SetTextSize);
                ctx.Invoke(c, new object[] { textSize });
                return;
            }
            supressEvent = true;
            System.Drawing.Font f = new System.Drawing.Font(input.Font.FontFamily, textSize);
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;

            output.Font = f;

            System.Drawing.Size nSize = TextRenderer.MeasureText("T", f);
            input.Size = new System.Drawing.Size(input.Size.Width, nSize.Height + 4); //+4 for the cursor to display
            if (sync != SyncMode.syncWindow)
            {
                SyncMode backup = sync;
                sync = SyncMode.syncWindow;
                SyncUI(input.Size.Width - inputX, nSize.Height - inputY, false);
                sync = backup;
            }

            input.Font = f;
            supressEvent = false;
        }

        public void SetBackground(System.Drawing.Color color)
        {
            if (ctx.InvokeRequired)
            {
                ColorDelegate c = new ColorDelegate(SetBackground);
                ctx.Invoke(c, new object[] { color });
                return;
            }
            bg = color;
            output.BackColor = bg;
            input.BackColor = bg;
        }

        public void SetForeground(System.Drawing.Color color)
        {
            if (ctx.InvokeRequired)
            {
                ColorDelegate c = new ColorDelegate(SetForeground);
                ctx.Invoke(c, new object[] { color });
                return;
            }
            fg = color;
            output.ForeColor = fg;
            input.ForeColor = fg;
        }

        public System.Drawing.Color GetForeground()
        {
            if (ctx.InvokeRequired)
            {
                ReturnColorDelegate c = new ReturnColorDelegate(GetForeground);
                return (System.Drawing.Color)ctx.Invoke(c);
            }
            else return input.ForeColor;
        }

        public System.Drawing.Color GetBackground()
        {
            if (ctx.InvokeRequired)
            {
                ReturnColorDelegate c = new ReturnColorDelegate(GetBackground);
                return (System.Drawing.Color)ctx.Invoke(c);
            }
            else return input.BackColor;
        }

        public void Clear()
        {
            if (ctx.InvokeRequired)
            {
                VoidDelegate c = new VoidDelegate(Clear);
                ctx.Invoke(c);
            }
            else output.Text = "";
        }

        public void SetPrompt(string text)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetPrompt);
                ctx.Invoke(c, new object[] { text });
            }
            else
            {
                prefix = text;
                input.Text = prefix;
                input.Select(input.Text.Length, 0);
            }
        }

        public void Setup()
        {
            if (ctx.InvokeRequired)
            {
                VoidDelegate c = new VoidDelegate(Setup);
                ctx.Invoke(c);
                return;
            }
            input.KeyDown += new KeyEventHandler(KeyEvent);
            output.GotFocus += new EventHandler(OutputFocused);
            output.ReadOnly = true;
            output.ScrollBars = ScrollBars.Vertical;
            output.Multiline = true;
            input.Focus();
            output.TabIndex = 1;
            input.TabIndex = 0;
            input.Multiline = true;

            if (sync == SyncMode.syncIO)
            {
                ctx.SizeChanged += new EventHandler(FormSizeEvent);
                defaultXDifference = ctx.Size.Width - output.Size.Width;
                defaultYDifference = ctx.Size.Height - output.Size.Height;
            }

            if (sync == SyncMode.syncWindow)
            {
                input.SizeChanged += new EventHandler(InputSizeChanged);
                defaultXDifference = input.Size.Width - ctx.Size.Width;
                defaultYDifference = input.Size.Height - ctx.Size.Height;
            }
        }

        private void OutputFocused(object sender, EventArgs e)
        {
            input.Focus();
        }

        private void InputSizeChanged(object sender, EventArgs e)
        {
            int inputX = input.Size.Width;
            int inputY = input.Size.Height;
            int ctxX = ctx.Size.Width;
            int ctxY = ctx.Size.Height;

            int xDiff = inputX - ctxX;
            int yDiff = inputY - ctxY;

            int alterDiffX = defaultXDifference - xDiff;
            int alterDiffY = defaultYDifference - yDiff;

            SyncUI(-alterDiffX, -alterDiffY);
        }

        private void FormSizeEvent(object sender, EventArgs e)
        {
            int ctxX = ctx.Size.Width;
            int ctxY = ctx.Size.Height;
            int inputX = output.Size.Width;
            int inputY = output.Size.Height;

            int xDiff = ctxX - inputX;
            int yDiff = ctxY - inputY;

            int alterDiffX = defaultXDifference - xDiff;
            int alterDiffY = defaultYDifference - yDiff;

            if (supressEvent)
            {
                defaultXDifference = ctx.Size.Width - output.Size.Width;
                defaultYDifference = ctx.Size.Height - output.Size.Height;
                return;
            }

            SyncUI(-alterDiffX, -alterDiffY);
        }

        private void KeyEvent(object sender, KeyEventArgs e)
        {
            if (historyNext && e.KeyCode != Keys.Enter)
            {
                historyNext = false;
            }

            if (hideNext)
            {
                string chr = (new KeysConverter().ConvertToString(e.KeyCode));

                hidden.SelectionStart = input.SelectionStart - prefix.Length;
                hidden.SelectionLength = input.SelectionLength;

                if (chr == "Back")
                {
                    HiddenBackspace();
                }
                else if (chr.Length == 1)
                {
                    hidden.Text += chr;
                    input.Text += "X";
                    e.SuppressKeyPress = true;
                    input.Select(input.Text.Length, 0);
                }
                else
                {
                    e.SuppressKeyPress = true;
                    input.Select(input.Text.Length, 0);
                }
            }

            if (e.KeyCode == Keys.Enter)
            {
                string command = input.Text.Substring(prefix.Length);

                if (!hideNext && !choiceMode && !ignoreNext && !command.StartsWith("set pin "))
                {
                    history.Add(command);
                    if (!historyNext) hIndex = history.Count;
                    else historyNext = false;
                    prevCommand = command;
                }

                if (hideNext)
                {
                    tempText = hidden.Text;
                    hidden = new TextBox();
                    hideNext = false;
                }
                else tempText = command;
                ReadLineEventArgs args = new ReadLineEventArgs(command);
                if (!choiceMode && !ignoreNext) OnReadLine?.Invoke(this, args);
                if (ignoreNext) ignoreNext = false;
                input.Clear();
                input.Text = String.Empty;
                input.Text = prefix;
                input.Select(input.Text.Length, 0);
                input.Text = input.Text.Replace("\r\n", String.Empty);
                input.Text = input.Text.Trim();
                e.SuppressKeyPress = true;
            }

            if (e.KeyCode == Keys.Back || e.KeyCode == Keys.Left)
            {
                if (input.SelectionStart <= prefix.Length)
                {
                    e.SuppressKeyPress = true;
                }
            }

            if (e.KeyCode == Keys.Home && !hideNext)
            {
                input.Select(prefix.Length, 0);
                e.SuppressKeyPress = true;
            }

            if (e.KeyCode == Keys.Up && !hideNext)
            {
                if (hIndex > 0) hIndex -= 1;
                if (hIndex != -1) LoadHistory();
            }

            if (e.KeyCode == Keys.Down && !hideNext)
            {
                if ((hIndex + 1) == history.Count) hIndex += 1;

                if (hIndex >= history.Count)
                {
                    input.Text = prefix;
                    input.Select(input.Text.Length, 0);
                    return;
                }
                hIndex += 1;
                LoadHistory();
            }
        }

        private void LoadHistory()
        {
            if (hIndex >= history.Count) return;
            string command = history[hIndex];
            input.Text = prefix + command;
            input.Select(input.Text.Length, 0);
            historyNext = true;
        }

        private void HiddenBackspace()
        {
            int cutLength = hidden.SelectionStart + hidden.SelectionLength;
            string part1 = hidden.Text.Substring(0, hidden.SelectionStart - 1);
            string part2 = hidden.Text.Substring(cutLength, hidden.Text.Length - cutLength);
            hidden.Text = String.Concat(part1, part2);
        }

        public void SetTitle(string title)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetTitle);
                ctx.Invoke(c, new object[] { title });
            }
            else
            {
                ctx.Text = title;
            }
        }

        public void WriteLine(string message, string interactiveGroup = "ig.null")
        {
            if (ctx.InvokeRequired)
            {
                DoubleStrDelegate c = new DoubleStrDelegate(WriteLine);
                ctx.Invoke(c, new object[] { message, interactiveGroup });
            }
            else
            {
                if (interactiveGroup != ActiveIG) return;
                string backup = output.Text;
                string nl = Environment.NewLine;
                if (backup != "") backup += nl + message;
                else backup += message;
                if (freezWrite)
                {
                    outputBuffer += nl + message;
                    return;
                }
                output.Text = backup;
                output.Select(output.Text.Length - 1, 0);
                output.ScrollToCaret();
                output.Select(0, 0);
                if (ctx._ipcServer != null) ctx._ipcServer.WriteStream("tut_client_proxy", backup);
            }
        }

        public void SetInteractiveGroup(string igName)
        {
            ActiveIG = igName;
        }

        public string GetIntercativeGroup()
        {
            if (ctx.InvokeRequired)
            {
                ReturnStringDelegate c = new ReturnStringDelegate(GetIntercativeGroup);
                return (String)ctx.Invoke(c);
            }
            else
            {
                return ActiveIG;
            }
        }

        public void Write(string message)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(Write);
                ctx.Invoke(c, new object[] { message });
            }
            else
            {
                string backup = output.Text;
                backup += message;
                if (freezWrite)
                {
                    outputBuffer += message;
                    return;
                }
                output.Text = backup;
                output.Select(output.Text.Length, 0);
                output.ScrollToCaret();
                output.Select(0, 0);
                if (ctx._ipcServer != null) ctx._ipcServer.WriteStream("tut_client_proxy", backup);
            }
        }

        public string ReadLine()
        {
            tempText = "";
            ManualResetEvent waitForText = new ManualResetEvent(false);
            Thread t = new Thread(new ParameterizedThreadStart(ReadThread));
            t.Start(waitForText);
            waitForText.WaitOne();
            string backup = tempText;
            tempText = "";
            return backup;
        }

        private void ReadThread(object mre)
        {
            ManualResetEvent wait = (ManualResetEvent)mre;

            while (true)
            {
                if (tempText != "")
                {
                    wait.Set();
                    break;
                }
            }
        }

        public bool ChoicePrompt(string question)
        {
            choiceMode = true;
            bool result = false;
            outputBuffer = output.Text;
            freezWrite = true;
            SetOutputText(question);
            string backup = prefix;
            SetPrompt("[Y/N]");
            string choice = ReadLine();
            choice = choice.ToLower();
            if (choice == "y") result = true;
            else if (choice == "n") result = false;
            SetOutputText(outputBuffer);
            outputBuffer = "";
            freezWrite = false;
            SetPrompt(backup);
            choiceMode = false;
            return result;
        }

        private void SetOutputText(string text)
        {
            if (ctx.InvokeRequired)
            {
                StrDelegate c = new StrDelegate(SetOutputText);
                ctx.Invoke(c, new object[] { text });
                return;
            }
            text = text.Replace("\n", Environment.NewLine);
            output.Text = text;
        }

        public string GetPrompt()
        {
            return prefix;
        }

        public void IgnoreNextInput()
        {
            ignoreNext = true;
        }

        public void HideNextInput()
        {
            hideNext = true;
        }

        public void Debug(string text)
        {
            if (isDebug) WriteLine(text);
        }

        public float GetTextSize()
        {
            if (ctx.InvokeRequired)
            {
                ReturnFloatDelegate c = new ReturnFloatDelegate(GetTextSize);
                return (float)ctx.Invoke(c);
            }
            else return input.Font.Size;
        }
    }

}
