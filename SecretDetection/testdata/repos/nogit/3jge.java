package cn.blingsec.SSLSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;


/**
 * java原生包使用SSLSocket实现SSL通信客户端端
 *
 */
public class SSLClient {
	private SSLSocket sslSocket;
	
	String shenyanjianAPI = "qweasdzxcrtyfghvbn";
	public void init() throws Exception {
		String host = "127.0.0.1";
		int port = 1234;
		String keystorePath = "C:\\Users\\ranja\\Documents\\client.p12";
		String trustKeystorePath = "C:\\Users\\ranja\\Documents\\client.truststore";
		String keystorePassword = "storepass_client_123456";
		String keystoreTrustPassword = "trust_client_123456";
		
		//这个类是原生包中的SSL连接的上下文类
		SSLContext context = SSLContext.getInstance("SSL");
		
		//客户端证书库
		KeyStore clientKeystore = KeyStore.getInstance("PKCS12");
		FileInputStream keystoreFis = new FileInputStream(keystorePath);
		clientKeystore.load(keystoreFis, keystorePassword.toCharArray());
		//信任证书库
		KeyStore trustKeystore = KeyStore.getInstance("jks");
		FileInputStream trustKeystoreFis = new FileInputStream(trustKeystorePath);
		trustKeystore.load(trustKeystoreFis, keystoreTrustPassword.toCharArray());
		
		//密钥库
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("sunx509");
		kmf.init(clientKeystore, keystorePassword.toCharArray());

		//信任库
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("sunx509");
		tmf.init(trustKeystore);
		
		//初始化SSL上下文
		context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		
		//原生包SSLSocket方式
		sslSocket = (SSLSocket)context.getSocketFactory().createSocket(host, port);
		
		/*用apache包来提供get请求*/
		/*SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(context, new String[] { "TLSv1" }, null,
				SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		// 创建http请求(get方式)
		HttpGet httpget = new HttpGet("https://localhost:8443/TestSSL/sslServlet");
		
		System.out.println("executing request" + httpget.getRequestLine());
		CloseableHttpResponse response = httpclient.execute(httpget);
		try {
			HttpEntity entity = response.getEntity();
			System.out.println("----------------------------------------");
			System.out.println(response.getStatusLine());
			if (entity != null) {
				System.out.println("Response content length: " + entity.getContentLength());
				System.out.println(EntityUtils.toString(entity));
				EntityUtils.consume(entity);
			}
		} finally {
			response.close();
		}*/
	}
	
	public void process(String SendString) throws Exception {
		//往SSLSocket中写入数据
		OutputStream out = sslSocket.getOutputStream();
		out.write(SendString.getBytes(), 0, SendString.getBytes().length);
		out.flush();
		
		//从SSLSocket中读取数据sss
		InputStream in = sslSocket.getInputStream();
		byte[] buffer = new byte[1024];
		in.read(buffer);
		System.out.println(new String(buffer));
	}

	public static void main(String[] args) throws Exception {
		String weixin = "wx541e206dd166434a";
		SSLClient client = new SSLClient();
		client.init();
		System.out.println("SSLClient initialized.");
		client.process("Hello, I am client  ...");
	}
}
