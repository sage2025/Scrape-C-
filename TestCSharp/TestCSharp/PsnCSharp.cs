using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

namespace TestCSharp
{
    public class PsnCSharp : IDisposable
    {
        public string m_strHeaderValue { get; private set; }
        public string m_strResponseValue { get; private set; }
        public string m_strContentValue { get; private set; }
        public string m_strCredentialValue { get; private set; }
        //
        //private const string V = "D:\\Working_d\\first_task\\to_Ayra(FINAL)\\finalproject\\proxidebug\\dll_project\\dllPsnFunk\\x64\\Release\\dllPsnFunk.dll";
        private const string V = "C:\\psn_funk_lib\\dllPsnFunk.dll";

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void FunctionPointer(IntPtr nb);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern void callCSharpFunction(IntPtr fctPointer);


        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr psnfunkmain(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr regMethodConfig(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr regMethodConfig2(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr crssConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);
        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr authConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr bindConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);
        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr kdpConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);
        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr capConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);
        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr cdpConfigMethod(IntPtr email, IntPtr pass, IntPtr consoleid, IntPtr proxy, int proxytype);

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr getToken(IntPtr navResponse, IntPtr proxy, int proxytype);


        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern void globalinitcurl();

        [DllImport(V, CallingConvention = CallingConvention.Cdecl)]
        public static extern void globacleanup();

        static IntPtr FctPtr;

        FunctionPointer MyFunctionPointer;

        void CallFunctionPointer(FunctionPointer cb)
        {
            // make sure the delegate isn't null
            if (null == cb) throw new ArgumentNullException("cb");

            // set our delegate place holder equal to the specified delegate
            MyFunctionPointer = cb;

            // Get a pointer to the delegate that can be passed to the C lib
            FctPtr = Marshal.GetFunctionPointerForDelegate(MyFunctionPointer);

            // call the imported function with that function pointer.
            callCSharpFunction(FctPtr);
        }

        public void printInConsole(IntPtr nb)
        {
            // Write the parameter in the console

            string strMesage;

            strMesage = Marshal.PtrToStringAnsi(nb);


            Console.WriteLine(strMesage);


        }

        public IntPtr printInConsolePtr;
        private bool disposedValue;

        void MainCall()
        {
            FunctionPointer printInConsoleDelegate;

            printInConsoleDelegate = new FunctionPointer(printInConsole);

            printInConsolePtr =
                Marshal.GetFunctionPointerForDelegate(printInConsoleDelegate);


            callCSharpFunction(printInConsolePtr);

            Console.ReadLine();
        }
        public static byte[] convert_unicode_to_ansi(string str)
        {
            string unicodeString = str;

            Encoding ascii = Encoding.ASCII;
            Encoding unicode = Encoding.Unicode;

            // Convert the string into a byte array.
            byte[] unicodeBytes = unicode.GetBytes(unicodeString);
            byte[] asciiBytes = Encoding.Convert(unicode, ascii, unicodeBytes);
            byte[] asciiBytesRes = new byte[asciiBytes.Length + 1];
            for (int i = 0; i < asciiBytes.Length; i++)
            {
                asciiBytesRes[i] = asciiBytes[i];
            }
            asciiBytesRes[asciiBytes.Length] = 0;
            // Perform the conversion from one encoding to the other.
            return asciiBytesRes;


        }

        public PsnCSharp()
        {
            FunctionPointer printInConsoleDelegate;

            printInConsoleDelegate = new FunctionPointer(printInConsole);

            printInConsolePtr =
                Marshal.GetFunctionPointerForDelegate(printInConsoleDelegate);

        }


        //Free Memory
        private void FreeAllocate(IntPtr var)
        {
            try
            {
                Marshal.FreeHGlobal(var);
            }
            catch (Exception e)
            {

            }
        }

        public async Task<string> Brute(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = psnfunkmain(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);

                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);

                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> GetToken(string r, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(r))
                {
                    return $"ERROR";
                }

                //if (string.IsNullOrEmpty(px))
                //{
                //    return $"ERROR";
                //}


                string navResponse = r;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrNavResponse = convert_unicode_to_ansi(navResponse);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }


                IntPtr inputBufferResponse = Marshal.AllocHGlobal(byteArrNavResponse.Length * sizeof(byte));
                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrNavResponse, 0, inputBufferResponse, byteArrNavResponse.Length);
                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);


                try
                {
                    var ret = getToken(inputBufferResponse, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);

                    FreeAllocate(inputBufferResponse);


                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n";

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferResponse);

                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> RegConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = regMethodConfig(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> RegConfig2(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = regMethodConfig2(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> CrssConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = crssConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> AuthConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = authConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);

                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);

                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> BindConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = bindConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }

        public async Task<string> kdpConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = kdpConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> capConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = capConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        public async Task<string> cdpConfig(string e, string p, string c, string px, int pxt = 0)
        {

            return await Task.Factory.StartNew(() =>
            {

                if (string.IsNullOrEmpty(e))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(p))
                {
                    return $"ERROR";
                }

                if (string.IsNullOrEmpty(c))
                {
                    return $"ERROR";
                }



                string email = e;
                string password = p;
                string consoleid = c;
                string proxy = px;
                int proxy_type = pxt;


                byte[] byteArrEmail = convert_unicode_to_ansi(email);
                byte[] byteArrpassword = convert_unicode_to_ansi(password);
                byte[] byteArrconsoleid = convert_unicode_to_ansi(consoleid);
                byte[] byteProxy = convert_unicode_to_ansi(proxy);
                if (proxy != "")
                {
                    byteProxy = convert_unicode_to_ansi(proxy);
                }
                else
                {
                    byte[] byteProxy1 = new byte[] { 0, 0, 0 };
                    byteProxy = byteProxy1;
                }



                IntPtr inputBufferemail = Marshal.AllocHGlobal(byteArrEmail.Length * sizeof(byte));

                IntPtr inputBufferpassword = Marshal.AllocHGlobal(byteArrpassword.Length * sizeof(byte));
                IntPtr inputBufferconsoleid = Marshal.AllocHGlobal(byteArrconsoleid.Length * sizeof(byte));

                IntPtr inputBufferproxy = Marshal.AllocHGlobal(byteProxy.Length * sizeof(byte));

                Marshal.Copy(byteArrEmail, 0, inputBufferemail, byteArrEmail.Length);
                Marshal.Copy(byteArrpassword, 0, inputBufferpassword, byteArrpassword.Length);
                Marshal.Copy(byteArrconsoleid, 0, inputBufferconsoleid, byteArrconsoleid.Length);

                Marshal.Copy(byteProxy, 0, inputBufferproxy, byteProxy.Length);



                try
                {
                    var ret = cdpConfigMethod(inputBufferemail, inputBufferpassword, inputBufferconsoleid, inputBufferproxy, proxy_type);
                    string responseString = Marshal.PtrToStringAnsi(ret);
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    if (string.IsNullOrEmpty(responseString))
                    {
                        return "ERROR-1";
                    }


                    string combine = "______________________";
                    string[] resultStr = responseString.Split(combine);

                    m_strHeaderValue = "";
                    m_strResponseValue = "";
                    m_strContentValue = "";
                    m_strCredentialValue = "";
                    if (resultStr.Length == 5)
                    {
                        m_strHeaderValue = resultStr[0];
                        m_strResponseValue = resultStr[1];
                        m_strCredentialValue = resultStr[3];
                        m_strContentValue = resultStr[0] + resultStr[1];

                        string result1 = "HEADER_DATA\n" + m_strHeaderValue
                        + "\nRESPONSE_DATA\n" + m_strResponseValue + "\nCONTENT_DATA\n"
                        + m_strContentValue + "\nCREDENTIAL:\n" + "" + e
                        + ":" + p + "," + px;

                        return result1;
                    }

                    return "\nERROR:" + responseString + "\nCREDENTIAL:\n" + " " + e
                        + ":" + p + "\n";
                }
                catch (SEHException ex)
                {
                    FreeAllocate(inputBufferemail);
                    FreeAllocate(inputBufferpassword);
                    FreeAllocate(inputBufferconsoleid);
                    FreeAllocate(inputBufferproxy);
                    Console.WriteLine(ex);
                    //  return ex.ToString();
                    return "ERROR-1";
                }
            });
        }
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                disposedValue = true;
            }
        }

        // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        // ~PsnCSharp()
        // {
        //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        //     Dispose(disposing: false);
        // }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
