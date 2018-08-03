using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

// ���ļ�Ϊ C# demo��ʹ�õķ��й�ģʽ�� C++ �ӿ�
// ��Ŀ��ʹ�� C# ���� dllsigcheck.dll ʱ��ע��ƽ̨��64 λ�� 32 λƽ̨�� dll ���Ǿ���Ԥ����

namespace csdemo
{
    class Program
    {
        // ����Ĺ�˽Կ·�����Ǿ���·�����뿪���������޸�
        const string pri_key_path = @"D:\src\oicq64\tinyid\tls_sig_api\example\cs\ec_key.pem";
        const string pub_key_path = @"D:\src\oicq64\tinyid\tls_sig_api\example\cs\public.pem";

        static void Main(string[] args)
        {
            // ���� sig �ļ�
            FileStream f = new FileStream(pri_key_path, FileMode.Open, FileAccess.Read);
            BinaryReader reader = new BinaryReader(f);
            byte[] b = new byte[f.Length];
            reader.Read(b, 0, b.Length);
            string pri_key = Encoding.Default.GetString(b);

            StringBuilder sig = new StringBuilder(4096);
            StringBuilder err_msg = new StringBuilder(4096);
            int ret = sigcheck.tls_gen_sig_ex(
                1400000377,
                "group_root",
                sig,
                4096,
                pri_key,
                (UInt32)pri_key.Length,
                err_msg,
                4096);
            if (0 != ret)
            {
                Console.WriteLine("err_msg: " + err_msg);
                return;
            }
            Console.WriteLine("\n-----\n");
            Console.WriteLine("gen sig:\n\n"+sig);

            // У�� sig
            f = new FileStream(pub_key_path, FileMode.Open, FileAccess.Read);
            reader = new BinaryReader(f);
            b = new byte[f.Length];
            reader.Read(b, 0, b.Length);
            string pub_key = Encoding.Default.GetString(b);

            UInt32 expire_time = 0;
            UInt32 init_time = 0;
            ret = sigcheck.tls_vri_sig_ex(
                sig.ToString(),
                pub_key,
                (UInt32)pub_key.Length,
                1400000377,
                "group_root",
                ref expire_time,
                ref init_time,
                err_msg,
                4096);

            if (0 != ret)
            {
                Console.WriteLine("err_msg: " + err_msg);
                return;
            }

            Console.WriteLine("\n-----\n");
            Console.WriteLine("verify ok -- expire time " + expire_time + " -- init time " + init_time);
            Console.WriteLine("\n-----\n");
            Console.ReadKey();
        }
    }

    class dllpath
    {
        // �����ߵ��� dll ʱ��ע����Ŀ��ƽ̨���ԣ������·���� demo ����ʱʹ�õģ����Լ�ʹ�������޸�
        // ��ʹ���ʵ���ƽ̨ dll
        //public const string DllPath = @"D:\src\oicq64\tinyid\tls_sig_api\windows\64\lib\libsigcheck\sigcheck.dll";       // 64 λ
        // ���ѡ�� Any CPU ƽ̨��Ĭ�ϼ��� 32 λ dll
        public const string DllPath = @"D:\src\oicq64\tinyid\tls_sig_api\windows\32\lib\libsigcheck\sigcheck.dll";     // 32 λ
    }

    class sigcheck
    {
        [DllImport(dllpath.DllPath, EntryPoint = "tls_gen_sig", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static int tls_gen_sig(
            UInt32 expire,
            string appid3rd,
            UInt32 sdkappid,
            string identifier,
            UInt32 acctype,
            StringBuilder sig,
            UInt32 sig_buff_len,
            string pri_key,
            UInt32 pri_key_len,
            StringBuilder err_msg,
            UInt32 err_msg_buff_len
        );

        [DllImport(dllpath.DllPath, EntryPoint = "tls_vri_sig", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static int tls_vri_sig(
            string sig,
            string pub_key,
            UInt32 pub_key_len,
            UInt32 acctype,
            string appid3rd,
            UInt32 sdkappid,
            string identifier,
            StringBuilder err_msg,
            UInt32 err_msg_buff_len
        );

        [DllImport(dllpath.DllPath, EntryPoint = "tls_gen_sig_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static int tls_gen_sig_ex(
            UInt32 sdkappid,
            string identifier,
            StringBuilder sig,
            UInt32 sig_buff_len,
            string pri_key,
            UInt32 pri_key_len,
            StringBuilder err_msg,
            UInt32 err_msg_buff_len
        );

        [DllImport(dllpath.DllPath, EntryPoint = "tls_vri_sig_ex", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public extern static int tls_vri_sig_ex(
            string sig,
            string pub_key,
            UInt32 pub_key_len,
            UInt32 sdkappid,
            string identifier,
            ref UInt32 expire_time,
            ref UInt32 init_time,
            StringBuilder err_msg,
            UInt32 err_msg_buff_len
        );
    }
}
