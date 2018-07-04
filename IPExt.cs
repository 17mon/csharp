using System;
using System.IO;
using System.Text;

namespace IP
{
    class IPExt
    {
        private static void Main(string[] args)
        {
            IPExt.EnableFileWatch = true;
            IPExt.Load("17monipdb.datx");

            Console.WriteLine(String.Join(", ", IPExt.Find("8.8.8.8")));
            Console.WriteLine(String.Join(", ", IPExt.Find("118.28.8.8")));
            Console.WriteLine(String.Join(", ", IPExt.Find("255.255.255.255")));
            Console.ReadKey(true);
        }

        public static bool EnableFileWatch = false;

        private static int offset;
        private static uint[] index = new uint[65536];
        private static byte[] dataBuffer;
        private static byte[] indexBuffer;
        private static long lastModifyTime = 0L;
        private static string ipFile;
        private static readonly object @lock = new object();

        public static void Load(string filename)
        {
            ipFile = new FileInfo(filename).FullName;
            Load();
            if (EnableFileWatch)
            {
                Watch();
            }
        }

        public static string[] Find(string ip)
        {
            lock (@lock)
            {
                var ips = ip.Split('.');
                var ip_prefix_value = Int32.Parse(ips[0]) * 256 + Int32.Parse(ips[1]);
                long ip2long_value = BytesToLong(Byte.Parse(ips[0]), Byte.Parse(ips[1]), Byte.Parse(ips[2]),
                    Byte.Parse(ips[3]));
                var start = index[ip_prefix_value];
                var max_comp_len = offset - 262144 - 4;
                long index_offset = -1;
                long index_length = -1;
                byte b = 0;
                for (start = start * 9 + 262144; start < max_comp_len; start += 9)
                {
                    if (
                        BytesToLong(indexBuffer[start + 0], indexBuffer[start + 1], indexBuffer[start + 2],
                            indexBuffer[start + 3]) >= ip2long_value)
                    {
                        index_offset = BytesToLong(b, indexBuffer[start + 6], indexBuffer[start + 5],
                            indexBuffer[start + 4]);
                        index_length = BytesToLong(b, b, indexBuffer[start + 7], indexBuffer[start + 8]);
                        break;
                    }
                }
                var areaBytes = new byte[index_length];
                Array.Copy(dataBuffer, offset + (int)index_offset - 262144, areaBytes, 0, index_length);
                return Encoding.UTF8.GetString(areaBytes).Split('\t');
            }
        }

        private static void Watch()
        {
            var file = new FileInfo(ipFile);
            if (file.DirectoryName == null) return;
            var watcher = new FileSystemWatcher(file.DirectoryName, file.Name) { NotifyFilter = NotifyFilters.LastWrite };
            watcher.Changed += (s, e) =>
            {
                var time = File.GetLastWriteTime(ipFile).Ticks;
                if (time > lastModifyTime)
                {
                    Load();
                }
            };
            watcher.EnableRaisingEvents = true;
        }

        private static void Load()
        {
            lock (@lock)
            {
                var file = new FileInfo(ipFile);
                lastModifyTime = file.LastWriteTime.Ticks;
                try
                {
                    dataBuffer = new byte[file.Length];
                    using (var fin = new FileStream(file.FullName, FileMode.Open, FileAccess.Read))
                    {
                        fin.Read(dataBuffer, 0, dataBuffer.Length);
                    }

                    var indexLength = BytesToLong(dataBuffer[0], dataBuffer[1], dataBuffer[2], dataBuffer[3]);
                    indexBuffer = new byte[indexLength];
                    Array.Copy(dataBuffer, 4, indexBuffer, 0, dataBuffer.Length - 4);
                    offset = (int)indexLength;

                    for (var i = 0; i < 256; i++)
                    {
                        for (var j = 0; j < 256; j++)
                        {
                            index[i * 256 + j] = BytesToLong(
                                indexBuffer[(i * 256 + j) * 4 + 3],
                                indexBuffer[(i * 256 + j) * 4 + 2],
                                indexBuffer[(i * 256 + j) * 4 + 1],
                                indexBuffer[(i * 256 + j) * 4]);
                        }
                    }
                }
                catch { }
            }
        }

        private static uint BytesToLong(byte a, byte b, byte c, byte d)
        {
            return ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;
        }
    }
}
