/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proteus;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import static java.lang.System.out;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.*;
import java.text.ParseException;
import java.util.Base64;

/**
 *
 * @author zhangjun
 */
public class APKAuthVerify {

    static String signFilePath = "a.apk.sign";
    static String certFilePath = "MPS_APK_AUTH.cer";
    static String fileSha1 = "C7D7921148E9E947249BF911FA7010EE94EC2DB0";
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, IOException, ParseException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // TODO code application logic here
        FileReader fr = new FileReader(signFilePath);
        BufferedReader br = new BufferedReader(fr);
        String s = br.readLine();
        String authDateString = s.substring(s.indexOf(':')+1).trim();

        s = br.readLine();
        String signatureString = s.substring(s.indexOf(':')+1).trim();
        byte[] signature = Base64.getDecoder().decode(signatureString);
//        out.println(toHexString(signature));
       
        byte[] signData = (fileSha1+authDateString).getBytes();
        
        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certFilePath));
        
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(cert);
        sig.update(signData);
        
        out.println(sig.verify(signature));
    }
    
    static String toHexString(byte[] value)
    {
        StringBuffer sb = new StringBuffer();
        for (int i=0;i<value.length;i++)
        {
            String s = Integer.toHexString(value[i]&0xFF);
            if  (s.length()<2) 
            sb.append(0);
            sb.append(s);
        }
        return sb.toString();
    }
    
}
