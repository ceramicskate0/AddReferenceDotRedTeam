using System;
using System.Text;
using System.IO;
using System.Net;
using System.Xml;

namespace AddReferenceDotRedTeam
{
    public class Cradles
    {
        public static byte[] Download_WebCLient_Data(string URL)
        {
            WebClient WC = new WebClient();
            IWebProxy defaultProxy = WebRequest.DefaultWebProxy;
            if (defaultProxy != null)
            {
                defaultProxy.Credentials = CredentialCache.DefaultCredentials;
                WC.Proxy = defaultProxy;
            }
            return WC.DownloadData(URL);
        }

        public static string Download_WebCLient_String(string URL)
        {
            WebClient WC = new WebClient();
            IWebProxy defaultProxy = WebRequest.DefaultWebProxy;
            if (defaultProxy != null)
            {
                defaultProxy.Credentials = CredentialCache.DefaultCredentials;
                WC.Proxy = defaultProxy;
            }
            return WC.DownloadString(URL);
        }

        public static string GET_XMLHTTP_Data(string URL)
        {
            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create(URL);
            HttpWebResponse resp = (HttpWebResponse)req.GetResponse();
            StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8);
            string data = sr.ReadToEnd();
            sr.Close();
            return data;
        }

        public static XmlDocument GET_XML_Load(string URL)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            try
            {
                doc.Load(URL);
                return doc;
            }
            catch (System.IO.FileNotFoundException)
            {
                return null;
            }
        }

        public static string Download_WinHttpRequest_(string URL)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URL);
            request.MaximumAutomaticRedirections = 4;
            request.MaximumResponseHeadersLength = 4;
            request.Credentials = CredentialCache.DefaultCredentials;
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream receiveStream = response.GetResponseStream();
            StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8);
            string Data=readStream.ReadToEnd();
            response.Close();
            readStream.Close();
            return Data;
        }

        public static string Read_File_OUT_to_String(string FilePath)
        {
            return File.ReadAllText(FilePath, Encoding.UTF8);
        }

        public static byte[] Read_File_Out_to_Bytes(string FilePath)
        {
            return File.ReadAllBytes(FilePath);
        }
    }
}
