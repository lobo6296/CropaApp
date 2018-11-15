package info.androidhive.loginandregistration.activity;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import android.annotation.SuppressLint;
//import com.sun.org.apache.xml.internal.security.utils.Base64;
import android.util.Base64;

@SuppressLint({ "SimpleDateFormat", "TrulyRandom" })
public class WsseToken {	
	public static final String HEADER_AUTHORIZATION = "Authorization";
	public static final String HEADER_WSSE = "X-WSSE";
	
	private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
	//in our case, User is an entity (just a POJO) persisted into sqlite database
	private User user;
	private String nonce;
	private String createdAt;
	//private String digest;

	public WsseToken(User user) {
		//we need the user object because we need his username
		this.user = user;
		this.createdAt = generateTimestamp();
		this.nonce = generateNonce();
		//this.digest = generateDigest();
	}

	private String generateNonce() {
		SecureRandom random = new SecureRandom();
		byte seed[] = random.generateSeed(10);
		return bytesToHex(seed);
	}
	
	public static String bytesToHex(byte[] bytes) {
	 final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	 char[] hexChars = new char[bytes.length * 2];
	 int v;
	 for ( int j = 0; j < bytes.length; j++ ) {
	 v = bytes[j] & 0xFF;
	 hexChars[j * 2] = hexArray[v >>> 4];
	 hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	 }
	 return new String(hexChars);
	}

	private String generateTimestamp() {
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		return sdf.format(new Date());
	}
/*
	private String generateDigest() {
		String digest = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			StringBuilder sb = new StringBuilder();
			sb.append(this.nonce);
			sb.append(this.createdAt);
			sb.append(this.user.getPassword());
			byte sha[] = md.digest(sb.toString().getBytes());
			digest = Base64.encodeToString(sha,Base64.NO_WRAP);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return digest;
	}
	*/
	private String getBASE64(String cadena) {
		byte[] data;
		String base64="";
		try {
			data = cadena.getBytes("UTF-8");
			base64 = Base64.encodeToString(data, Base64.DEFAULT);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return base64;
	}

	public String getWsseHeader() {
		StringBuilder header = new StringBuilder();
/*
		header.append("<wsse:UsernameToken>");
		header.append("<wsse:Username>JRIVERA</wsse:Username>");
		header.append("<wsse:ENonce>"+this.nonce+"</wsse:ENonce>");
		header.append("<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"+this.digest+"</wsse:Password>");
        header.append("<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"+getBASE64(this.nonce)+"</wsse:Nonce>");
		header.append("<wsu:Created>"+this.createdAt+"</wsu:Created>");
		header.append("</wsse:UsernameToken>");
*/
		header.append("<wsse:Security soapenv:mustUnderstand='1' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>");
		header.append("<wsse:UsernameToken>");
		header.append("<wsse:Username>JRIVERA</wsse:Username>");
		header.append("<wsse:Password>j$t56e&amp;%</wsse:Password>");
		header.append("</wsse:UsernameToken>");
		header.append("</wsse:Security>");

		return header.toString();
	}
	
	public String getAuthorizationHeader() {
		return "WSSE profile=\"UsernameToken\"";
	}
}