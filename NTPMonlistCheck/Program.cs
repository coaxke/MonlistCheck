using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;

namespace NTPMonlistCheck
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("This tool will advise if an NTP Server is responding to a MON_GETLIST request");
            Console.WriteLine("If it does, this could potentially be used to perform NTP Based DDoS attacks \n");

            Console.Write("Please enter the NTP Server Name/IP Address: ");
            string ntpServer = Console.ReadLine();

            Console.WriteLine("\nChecking to see if server is a Valid NTP server and will return time...");


            var ntpData = new byte[48]; //Initialize byte array for Data we wish to send
            var ntpReceive = new byte[48]; //Initialize byte array for Data we wish to receive
            ntpData[0] = 0x1B; //NTP Magic data - LeapIndicator = 0 (no warning), VersionNum = 3 (IPv4 only), Mode = 3 (Client Mode)
            
            
            var addresses = Dns.GetHostEntry(ntpServer).AddressList;
            var ipEndPoint = new IPEndPoint(addresses[0], 123);
            
            //Create new instance of a Socket  with params defined above
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                Console.WriteLine("Attempting to connect to {0}", ntpServer.ToString());
                socket.ReceiveTimeout = 5000; //Set Limit of 5 seconds for connection
                socket.Connect(ipEndPoint);
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Could not connect to NTP Server {0} - Check that UDP Port 123 is not being blocked by something like a firewall...", ntpServer.ToString());
                Console.ResetColor();
                Console.WriteLine("Press Any key to exit.");
                Console.ReadKey();
                Environment.Exit(0); //Exit with a Success code... even though it isnt really.
            }


            socket.Send(ntpData); //Send the NTP Time Request.
            
            try
            {
                //Attempt to recieve the response from NTP Server
                socket.Receive(ntpReceive);
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Did not receive a response from the remote NTP Server {0} - Check that UDP Port 123 is not being blocked by something like a firewall...", ntpServer.ToString());
                Console.ResetColor();
                Console.WriteLine("Press Any key to exit.");
                Console.ReadKey();
                Environment.Exit(0); //Exit with a Success code... even though it isnt really.
            }
            

            if (ntpReceive.Count() > 0)
            {

                //Do some magic to convert the NTP response into human readable time
                ulong intPart = (ulong)ntpReceive[40] << 24 | (ulong)ntpReceive[41] << 16 | (ulong)ntpReceive[42] << 8 | (ulong)ntpReceive[43];
                ulong fractPart = (ulong)ntpReceive[44] << 24 | (ulong)ntpReceive[45] << 16 | (ulong)ntpReceive[46] << 8 | (ulong)ntpReceive[47];

                var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);
                var networkDateTime = (new DateTime(1900, 1, 1)).AddMilliseconds((long)milliseconds);

                Console.WriteLine("NTP Server responded with the following time:");
                Console.WriteLine(networkDateTime);
                
                Console.WriteLine("\nAttempting to check if the remote server will return MONLIST information...");

                byte[] monlistdata = new byte[] { 0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00 }; //Initialize byte array for MONLIST data we wish to send
                byte[] monlistdataReceive = new byte[1024]; //Initialize byte array for Monlist we wish to receive


                try
                {
                    Console.WriteLine("Attempting to connect to {0}", ntpServer.ToString());
                    socket.ReceiveTimeout = 5000; //Set Limit of 5 seconds for connection
                    socket.Connect(ipEndPoint);
                    
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Could not connect to NTP Server {0} - Check that UDP Port 123 is not being blocked by something like a firewall...", ntpServer.ToString());
                    Console.ResetColor();
                    Console.WriteLine("Press Any key to exit.");
                    Console.ReadKey();
                    Environment.Exit(0); //Exit with a Success code... even though it isnt really.
                }

                socket.Send(monlistdata); //Send the NTP Time Request.

                try
                {
                    //Attempt to recieve the response from NTP Server
                    socket.Receive(monlistdataReceive);
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("NTP Server {0} is NOT responding to a MON_GETLIST, that's great!", ntpServer.ToString());
                    Console.ResetColor();
                    Console.WriteLine("Press Any key to exit.");
                    Console.ReadKey();
                    Environment.Exit(0); //Exit with a Success code
                }

                //Clean up after ourselves and dispose of socket.           
                socket.Close();

                if (monlistdataReceive[7] == 72) 
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("NTP Server {0} IS returning Monlist information when MON_GETLIST, If you run this NTP server - please check https://www.us-cert.gov/ncas/alerts/TA14-013A/", ntpServer.ToString());
                    Console.WriteLine("Press Any key to exit.");
                    Console.ReadKey();
                    Console.ResetColor();
                    Environment.Exit(0); //Exit with a Success code.
                }
                                            
            }

            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No NTP response received from NTP Server {0} - Check that UDP Port 123 is not being blocked by something like a firewall...", ntpServer.ToString());
                Console.ResetColor();
                Console.WriteLine("Press Any key to exit.");
                Console.ReadKey();
                Environment.Exit(0); //Exit with a Success code... even though it isnt really.
            }
            
        }
    }
}
