package net.bplaced.javacrypto.pgpcryptography.pgp;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: George El-Haddad
* Copyright/Copyright: George El-Haddad
* Lizenttext/Licence: BSD 3-Clause License 
* https://github.com/java-crypto/PGP-Encryption-and-Signature/blob/master/LICENSE
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 26.02.2020
* Funktion: testet die PGP-Helper-Datei PGPCryptoTools.java
* Function: tester for PGPCryptoTools.java
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
* 
* Das originale Github-Archiv kann hier eingesehen werden:
* You can find the original Github-Repository with this link:
* https://github.com/george-haddad/bouncycastle
* 
* Sie benötigen die nachfolgenden Bibliotheken (alle im Github-Archiv im Unterordner "libs")
* You need the following libraries (see my Github-repository in subfolder "libs")
* Bouncy Castle: bcprov-jdk15on-164.jar, bcpg-jdk15on-164.jar, bcpkix-jdk15on-164.jar
* others: commons-io-2.4.jar, icu4j-3.4.4.jar, jasypt-1.9.1.jar
* my Github-Repository: https://github.com/java-crypto/PGP-Encryption-and-Signature
* libs in my Github-Repo: https://github.com/java-crypto/PGP-Encryption-and-Signature/tree/master/libs
* 
*/

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;

/**
 * 
 * Copyright George El-Haddad</br>
 * <b>Time stamp:</b> Dec 6, 2012 - 11:41:43 AM<br/>
 * @author George El-Haddad
 * <br/>
 *
 */
public class PGPCryptoBC {

        public PGPCryptoBC() {

        }

        public void generateKeyPair() {
                try {
                        String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";

                        BigInteger primeModulous = PGPKeyTools.getSafePrimeModulus(PGPKeyTools.PRIME_MODULUS_4096_BIT);
                        BigInteger baseGenerator = PGPKeyTools.getBaseGenerator();
                        ElGamalParameterSpec paramSpecs = new ElGamalParameterSpec(primeModulous, baseGenerator);

                        KeyPair dsaKeyPair = PGPKeyTools.generateDsaKeyPair(1024);
                        KeyPair elGamalKeyPair = PGPKeyTools.generateElGamalKeyPair(paramSpecs);

                        PGPKeyRingGenerator pgpKeyRingGen = PGPKeyTools.createPGPKeyRingGenerator(
                                        dsaKeyPair,
                                        elGamalKeyPair,
                                        "Greg House <g.house@gmail.com>",
                                        "TestPass12345!".toCharArray()
                                        );

                        File privateKey = new File(keysDir + File.separator + "secret4.asc");
                        File publicKey = new File(keysDir + File.separator + "public4.asc");

                        PGPKeyTools.exportSecretKey(pgpKeyRingGen, privateKey, true);
                        PGPKeyTools.exportPublicKey(pgpKeyRingGen, publicKey, true);

                        System.out.println("Generated private key: " + privateKey.getAbsolutePath());
                        System.out.println("Generated public key: " + publicKey.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void signFileDetached() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File theFile = new File(filesDir + File.separator + "TheFile.txt");
                File keyRingFile = new File(keysDir + File.separator + "secret4.asc");
                File signatureFile = new File(filesDir + File.separator + "TheFile.txt.sig");

                try {
                        PGPCryptoTools.signFileDetached(theFile, keyRingFile, signatureFile, "TestPass12345!".toCharArray(), false);
                        System.out.println("File to sign: " + theFile.getAbsolutePath());
                        System.out.println("Signing key: " + keyRingFile.getAbsolutePath());
                        System.out.println("Signed file: " + signatureFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void verifyFileDetached() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                //File publicKeyFile = new File(keysDir + File.separator + "public.asc");
                File publicKeyFile = new File(keysDir + File.separator + "public4.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.txt");
                File signatureFile = new File(filesDir + File.separator + "TheFile.txt.sig");

                try {
                        boolean verified = PGPCryptoTools.verifyFileDetached(signedFile, signatureFile, publicKeyFile);
                        System.out.println("File: " + signedFile.getAbsolutePath());
                        System.out.println("Verified: " + verified);
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void signFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File theFile = new File(filesDir + File.separator + "TheFile.txt");
                File keyRingFile = new File(keysDir + File.separator + "secret4.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.pgp");

                try {
                        PGPCryptoTools.signFile(theFile, keyRingFile, signedFile, "TestPass12345!".toCharArray(), false);
                        System.out.println("File to sign: " + theFile.getAbsolutePath());
                        System.out.println("Signing key: " + keyRingFile.getAbsolutePath());
                        System.out.println("Signed file: " + signedFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void verifyFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File publicKeyFile = new File(keysDir + File.separator + "public4.asc");
                File signedFile = new File(filesDir + File.separator + "TheFile.pgp");

                try {
                        boolean verified = PGPCryptoTools.verifyFile(signedFile, publicKeyFile);
                        System.out.println("File: " + signedFile.getAbsolutePath());
                        System.out.println("Verified: " + verified);
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void encryptFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File textFile = new File(filesDir + File.separator + "TheFile.txt");
                File outputFile = new File(filesDir + File.separator + "TheFile.pgp");
                File publicKeyFile = new File(keysDir + File.separator + "public4.asc");

                try {
                        PGPCryptoTools.encryptFile(outputFile, textFile, publicKeyFile, true, true);
                        System.out.println("File: " + textFile.getAbsolutePath());
                        System.out.println("Encrypted to: " + outputFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void decryptFile() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                String filesDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/files";

                File textFile = new File(filesDir + File.separator + "TheFile.txt");
                File inputFile = new File(filesDir + File.separator + "TheFile.pgp");
                File secretKeyFile = new File(keysDir + File.separator + "secret4.asc");

                try {
                        PGPCryptoTools.decryptFile(inputFile, secretKeyFile, "TestPass12345!".toCharArray(), textFile);
                        System.out.println("File: " + inputFile.getAbsolutePath());
                        System.out.println("Decrypted to: " + textFile.getAbsolutePath());
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public void listPublicKeyCertifications() {
                String keysDir = System.getProperty("user.dir") + File.separator + "src/george/crypto/pgp/keys";
                //File publicKeyFile = new File(keysDir + File.separator + "MrBilly.asc");
                File publicKeyFile = new File(keysDir + File.separator + "public4.asc");

                try {
                        System.out.println("The public key was certified by: ");
                        List<String> keyIds = PGPCryptoTools.listCertifications(publicKeyFile);
                        for (String keyId : keyIds) {
                                System.out.println("\t" + keyId);
                        }
                }
                catch (Exception ex) {
                        ex.printStackTrace();
                }
        }

        public static void main(String ... args) {
        		Security.addProvider(new BouncyCastleProvider());

                // Un comment to test different crypto functions
                System.out.println("\nPGPCryptoBC by George El-Haddad");
                System.out.println("\n1 generateKeyPair");
                new PGPCryptoBC().generateKeyPair();
                System.out.println("\n2 signFile");
                new PGPCryptoBC().signFile();
                System.out.println("\n3 verifyFile");
                new PGPCryptoBC().verifyFile();
                System.out.println("\n4 signFileDetached");
                new PGPCryptoBC().signFileDetached();
                System.out.println("\n5 verifyFileDetached");
                new PGPCryptoBC().verifyFileDetached();
                System.out.println("\n6 encryptFile");
                new PGPCryptoBC().encryptFile();
                System.out.println("\n7 decryptFile");
                new PGPCryptoBC().decryptFile();
                System.out.println("\n8 listPublicKeyCertifications");
                new PGPCryptoBC().listPublicKeyCertifications();
        }
}
