using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestCSharp
{
    class Program
    {

        static void Main(string[] args)
        {

            test();


            Console.ReadKey();
        }

        public async static void test()
        {
           

            PsnCSharp psSerivce = new PsnCSharp();
            var result = await psSerivce.Brute("jamesdlt18@gmail.com", "tedford18", "000000010085000c1421156117764e1b00000000000000000000000000000000", "", 0);
            //var result = await psSerivce.GetToken("QQAAAAAAAAABNjAAAAABAAAIABSXYoEGTE5QWCRooCbw4YgQmZMvwABAAQAAAEAAAcACAAAAXkuQnDbAAcACAAAAXkzaMnAAAIACHq5Fw8gyI12AAQAIHBhdWxvX3ZlcmNlc2kAAAAAAAAAAAAAAAAAAAAAAAAAAAgABGJyAAcABAAEZDEAAAAIABhJVjAwMDEtTlBYUzAxMDAxXzAwAAAAAAAwEQAEB8IFEwABAAQiAAIAMBAAAAAAAAAAAAAAAAgACFBTM19DAAAAAAgAQAIAr714C5L7RugQY/65LrOHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAgAsAAgABDTNPKkACAAg8Q9IcPXQXS1wKiI17MSIvNqsDITYHaT375pVxM/XZJ0=", "",0);
            Console.WriteLine();
            Console.WriteLine("------------------ Response ------------------");
            string navResponse = psSerivce.m_strResponseValue;
            Console.WriteLine(result);
            psSerivce?.Dispose();



            Console.ReadKey();
         
        }


    }

}
