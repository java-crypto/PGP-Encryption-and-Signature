package net.bplaced.javacrypto.pgpcryptography.pbe;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: George El-Haddad
* Copyright/Copyright: George El-Haddad
* Lizenttext/Licence: BSD 3-Clause License 
* https://github.com/java-crypto/PGP-Encryption-and-Signature/blob/master/LICENSE
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 26.02.2020
* Funktion: testet PBE (Passwortbasierte Verschlüsselung) mit Bouncy Castle
* Function: test of PBE (passwort based encryption) with Bouncy Castle
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

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.salt.RandomSaltGenerator;

/**
 * 
 * Copyright George El-Haddad</br>
 * <b>Time stamp:</b> Dec 6, 2012 - 11:41:43 AM<br/>
 * @author George El-Haddad
 * <br/>
 *
 */
public class TestPbe {

        static {
                Security.addProvider(new BouncyCastleProvider());
        }

        public static void main(String... args) {
                PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
                encryptor.setProviderName("BC");
                encryptor.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
                encryptor.setPoolSize(4);
                encryptor.setSaltGenerator(new RandomSaltGenerator());
                encryptor.setKeyObtentionIterations(100000);
                encryptor.setPasswordCharArray("BadAssPassword12345!".toCharArray());

                String crypted = encryptor.encrypt("Hello World!");
                System.out.println(crypted);

                String plain = encryptor.decrypt(crypted);
                System.out.println(plain);

        }
}
