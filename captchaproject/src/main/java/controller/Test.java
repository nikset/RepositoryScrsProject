package controller;

/*import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		

//pin
			String captchaPin = "cioa";
			
			
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] encodedhash = digest.digest(
					captchaPin.getBytes(StandardCharsets.UTF_8));
			
			for(int i=0; i<encodedhash.length; i++){
				
				System.out.println(encodedhash[i]);
			}
				
			
			
			System.out.println(encodedhash);
			
			//pin
			
			
			//creazione algorimto di codifica AES
			
			*/
			
			
			
			import javax.crypto.Cipher;
			import javax.crypto.Mac;
			import javax.crypto.spec.IvParameterSpec;
			import javax.crypto.spec.SecretKeySpec;



import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
			import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

			public class Test {

			    public static void main(String[] args) throws Exception {
			    	
			    	
			    	
			    	
			    	String str = "ackfq5t08tv0g0fq1f5gnsltm9lir4x9=[B@2515d43";
			    	String stringaDaConfrontare=str.substring(0,32);
			    	
			    	System.out.println("LA STAMPAAAAAA è: "+stringaDaConfrontare );
			    	

			    	//sarebbe il vettore che esce estratto dallos stringone
			        String KeyCifratura = "4s0jx9drs25ni0l7y0dlx569qapjcbzg";
			        
			        //questa sarebbe la password (inserita in fase di registrazione) che deve essere cifrata con la chiave di sopra
			        String password = "luna";

			        //byte[] encrypted = encrypt(password, KeyCifratura);

			        //String encoded = Base64.getEncoder().encodeToString(encrypted);
			        //System.out.println("La criptografia produce: " + encoded);
			        
			        //Base64 Decoded
			        byte[] decoded = Base64.getDecoder().decode("dZ+oxbzF8uftTqPkR0cq+YOb4MhXcRAmNevZtnyWkAE=");
			        
			        
			      //lo decripto
			        String decrypted = decrypt(decoded, KeyCifratura);
			        
			        System.out.println("LA MIA PASSWORD é: "+ decrypted);
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        //scrittura - inizio
			        HashMap<String, String> ldapContent = new HashMap<String, String>();
			           //Adding elements to HashMap
			        ldapContent.put("13", "AB");
			        ldapContent.put("4", "CD");
			        ldapContent.put("35", "EF");
			        ldapContent.put("7", "GH");
			        ldapContent.put("23", "IJ");
			        ldapContent.put("altro", "nuovo");
			        ldapContent.put("ciao", "nuoco");
			        ldapContent.put("adesso", "nuoco");
			        
			        //salva informazioni in file di properties
			      //  Map<String, String> ldapContent = new HashMap<String, String>();
			        Properties properties = new Properties();

			        for (Map.Entry<String,String> entry : ldapContent.entrySet()) {
			            properties.put(entry.getKey(), entry.getValue());
			        }

			        properties.store(new FileOutputStream("data.properties"), null);
			        //scrittura -fine
			        
			        
			        //lettura -inizio
			        properties.load(new FileInputStream("data.properties"));
                    System.out.println("Il valore della chiave altro è :" + properties.getProperty("altro"));
                    //lettura -fine
			        
			        
			        
                    
                    
                  
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
			        
			        for (Map.Entry<String,String> entry : ldapContent.entrySet()) {
			            properties.put(entry.getKey(), entry.getValue());
			        }
			        
			        properties.store(new FileOutputStream("data.properties"), null);
			        
			        
			        
			        System.out.println(properties);
			        
			        
			      
			       
			            
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        for (String key1 : properties.stringPropertyNames()) {
			           ldapContent.put(key1, properties.get(key1).toString());
			        }
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        
			        HashMap<String, String> hmap = new HashMap<String, String>();
			           //Adding elements to HashMap
			        hmap.put("13", "AB");
			        hmap.put("4", "CD");
			        hmap.put("35", "EF");
			        hmap.put("7", "GH");
			        hmap.put("23", "IJ");
			        
			        
			       
			           try
			           {
			                  FileOutputStream fos =
			                     new FileOutputStream("hashmap.ser");
			                  ObjectOutputStream oos = new ObjectOutputStream(fos);
			                  oos.writeObject(hmap);
			                  oos.close();
			                  fos.close();
			                  System.out.printf("Serialized HashMap data is saved in hashmap.ser");
			           }catch(IOException ioe)
			            {
			                  ioe.printStackTrace();
			            }
			        

			        
			        
			        HashMap<Integer, String> map = null;
			        try
			        {
			           FileInputStream fis = new FileInputStream("hashmap.ser");
			           ObjectInputStream ois = new ObjectInputStream(fis);
			           map = (HashMap) ois.readObject();
			           ois.close();
			           fis.close();
			        }catch(IOException ioe)
			        {
			           ioe.printStackTrace();
			           return;
			        }catch(ClassNotFoundException c)
			        {
			           System.out.println("Class not found");
			           c.printStackTrace();
			           return;
			        }
			        System.out.println("Deserialized HashMap..");
			        // Display content using Iterator
			        Set set = map.entrySet();
			        Iterator iterator = set.iterator();
			        while(iterator.hasNext()) {
			           Map.Entry mentry = (Map.Entry)iterator.next();
			           System.out.print("key: "+ mentry.getKey() + " & Value: ");
			           System.out.println(mentry.getValue());
			        }
			      }
			        
			        
			        
			        
			        
			        
			        
			    
			    
			    
			    

			    public static byte[] encrypt(String plainText, String key) throws Exception {
			        byte[] clean = plainText.getBytes();

			        // Generating IV.
			        int ivSize = 16;
			        byte[] iv = new byte[ivSize];
			        SecureRandom random = new SecureRandom();
			        random.nextBytes(iv);
			        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			        // Hashing key.
			        MessageDigest digest = MessageDigest.getInstance("SHA-256");
			        digest.update(key.getBytes("UTF-8"));
			        
			        
			        
			        byte[] keyBytes = new byte[16];
			        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
			        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

			        // Encrypt.
			        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			        byte[] encrypted = cipher.doFinal(clean);

			        // Combine IV and encrypted part.
			        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
			        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
			        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

			        return encryptedIVAndText;
			    }

			    public static String decrypt(byte[] encryptedIvTextBytes, String key) throws Exception {
			        int ivSize = 16;
			        int keySize = 16;

			        // Extract IV.
			        byte[] iv = new byte[ivSize];
			        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
			        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			        // Extract encrypted part.
			        int encryptedSize = encryptedIvTextBytes.length - ivSize;
			        byte[] encryptedBytes = new byte[encryptedSize];
			        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

			        // Hash key.
			        byte[] keyBytes = new byte[keySize];
			        MessageDigest md = MessageDigest.getInstance("SHA-256");
			        md.update(key.getBytes());
			        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
			        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

			        // Decrypt.
			        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
			        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

			        return new String(decrypted);
			    }
			}