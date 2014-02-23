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

            const string ntpServer = "192.168.0.201";
            //var ntpData = new byte[48];
            //ntpData[0] = 0x1B; //LeapIndicator = 0 (no warning), VersionNum = 3 (IPv4 only), Mode = 3 (Client Mode)
            //ntpData[0] = (\x17\x00\x03\x2a" + "\x00" * 4);
            //ntpData[0] = ("\x17\x00\x03\x2a") + ("\x00");

            byte[] ntpData = new byte[] { 0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00 };
            byte[] ntpdataback = new byte[1024];
            

           // byte[] ntpData = Encoding.UTF8.GetBytes(("\x17\x00\x03\x2a") + ("\x00") + ("\x00") + ("\x00") + ("\x00"));

            var addresses = Dns.GetHostEntry(ntpServer).AddressList;
            var ipEndPoint = new IPEndPoint(addresses[0], 123);
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            socket.Connect(ipEndPoint);
            socket.Send(ntpData);
            socket.Receive(ntpdataback);
            socket.Close();

            //ulong intPart = (ulong)ntpData[40] << 24 | (ulong)ntpData[41] << 16 | (ulong)ntpData[42] << 8 | (ulong)ntpData[43];
            //ulong fractPart = (ulong)ntpData[44] << 24 | (ulong)ntpData[45] << 16 | (ulong)ntpData[46] << 8 | (ulong)ntpData[47];

            //var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);
            //var networkDateTime = (new DateTime(1900, 1, 1)).AddMilliseconds((long)milliseconds);

            //Console.WriteLine(networkDateTime);
            //Console.WriteLine(ntpData.Count());
            //Console.WriteLine(ntpData[0].ToString());
            Console.WriteLine(ntpdataback.Count());
            Console.WriteLine(ntpdataback[7]);
            Console.ReadLine();



        }
    }
}
