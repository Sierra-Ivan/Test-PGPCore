using System;
using System.IO;
using System.Text;
using PgpCore;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Test_PGP
{
    public static class Program
    {
        static void Main()
        {
            // 1 - Contraseñas para las claves privadas
            string passA = "claveA";
            string passB = "claveB";

            // generar claves en memoria
            string A_public, A_private, B_public, B_private;
            GenerateKeyPair(out A_public, out A_private, passA, "A@example.com");
            GenerateKeyPair(out B_public, out B_private, passB, "B@example.com");

            Console.WriteLine("Claves generadas para A y B\n");

            // 2 - A → B: mensaje cifrado
            string mensajeA = "Hola B, soy A. Este es un mensaje cifrado con PGP.";

            string mensajeCifradoParaB = EncryptMessage(mensajeA, B_public);
            Console.WriteLine("A -> B: mensaje cifrado enviado.\n");
            Console.WriteLine(mensajeCifradoParaB + "\n");

            // 3 - B descifra el mensaje
            string mensajeDescifradoPorB = DecryptMessage(mensajeCifradoParaB, B_private, passB);
            Console.WriteLine($"B recibió y descifró: {mensajeDescifradoPorB}\n");

            // 4 - B → A: mensaje cifrado y firmado
            string mensajeB = "Hola A, soy B. Recibí tu mensaje correctamente.";
            string mensajeCifradoYFirmadoParaA = EncryptAndSignMessage(mensajeB, A_public, B_private, passB);
            Console.WriteLine("B -> A: mensaje cifrado y firmado enviado.\n");
            Console.WriteLine(mensajeCifradoYFirmadoParaA + "\n");

            // 5 - A descifra y verifica firma
            string mensajeDescifradoPorA = DecryptAndVerifyMessage(mensajeCifradoYFirmadoParaA, B_public, A_private, passA);
            Console.WriteLine(mensajeDescifradoPorA + "\n");
        }

        // ============================================================
        // FUNCIONES AUXILIARES
        // ============================================================

        static void GenerateKeyPair(out string publicKey, out string privateKey, string passphrase, string identity)
        {
            var pgp = new PGP();
            var pubStream = new MemoryStream();
            var privStream = new MemoryStream();

            pgp.GenerateKey(pubStream, privStream, identity, passphrase);

            publicKey = Encoding.UTF8.GetString(pubStream.ToArray());
            privateKey = Encoding.UTF8.GetString(privStream.ToArray());
        }

        static string EncryptMessage(string plainText, string publicKey)
        {
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey);
            var pgp = new PGP(encryptionKeys);
            var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(plainText));
            var outputStream = new MemoryStream();

            pgp.EncryptStream(inputStream, outputStream, true, true);

            return Encoding.UTF8.GetString(outputStream.ToArray());
        }

        static string DecryptMessage(string encryptedText, string privateKey, string passphrase)
        {
            EncryptionKeys encryptionKeys = new EncryptionKeys(privateKey, passphrase);
            var pgp = new PGP(encryptionKeys);
            var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(encryptedText));
            var outputStream = new MemoryStream();

            pgp.DecryptStream(inputStream, outputStream);
            return Encoding.UTF8.GetString(outputStream.ToArray());
        }

        static string EncryptAndSignMessage(string plainText, string publicKey, string privateKey, string passphrase)
        {
            EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, passphrase);
            var pgp = new PGP(encryptionKeys);
            var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(plainText));
            var outputStream = new MemoryStream();

            pgp.EncryptStreamAndSign(inputStream, outputStream, true, true);
            return Encoding.UTF8.GetString(outputStream.ToArray());
        }


        public static string DecryptAndVerifyMessage(string plainText, string publicKey, string privateKey, string passphrase)
        {
            try
            {
                EncryptionKeys encryptionKeys = new EncryptionKeys(publicKey, privateKey, passphrase);
                var pgp = new PGP(encryptionKeys);
                var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(plainText));
                var outputStream = new MemoryStream();
                pgp.DecryptAndVerify(inputStream, outputStream);
                return Encoding.UTF8.GetString(outputStream.ToArray());
            }
            catch (PgpException)
            {
                return ("ERROR PGP DETECTADO: La clave o la firma son incorrectas.");
            }
            catch (IOException ioEx)
            {
                return ($"ERROR DE ENTRADA/SALIDA: Mensaje: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                return ($"ERROR DESCONOCIDO: Mensaje: {ex.Message}");
            }
        }
    }
}