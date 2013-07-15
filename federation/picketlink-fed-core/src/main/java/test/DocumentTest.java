package test;

import org.picketlink.identity.federation.core.config.AuthPropertyType;
import org.picketlink.identity.federation.core.config.KeyProviderType;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyConfigurationException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.interfaces.TrustKeyProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class DocumentTest {

	/**
	 * @param args
	 * @throws ProcessingException 
	 * @throws ParsingException 
	 * @throws ConfigurationException 
	 */
	public static void main(String[] args) throws Exception {
		Document document = DocumentUtil.getDocument("<CardHolderData><Card><Id>1</Id></Card><Card><Id>2</Id></Card><Contact><FirstName>Charles</FirstName></Contact></CardHolderData>");
		System.out.println(document.getDocumentElement());
		System.out.println(document.getElementsByTagName("Card").getLength());
		Element cardElement = (Element) document.getElementsByTagName("Card").item(0);
		
		System.out.println(DocumentUtil.getNodeAsString(document.getDocumentElement()));
		System.out.println(DocumentUtil.getNodeAsString(cardElement));
		System.out.println(document.getElementsByTagName("Contact").getLength());
		System.out.println(document.getElementsByTagName("Non").getLength());

		TrustKeyManager keyManager = getKeyManager();
		System.out.println(keyManager.getEncryptionKey("all", "AES", 128));
		System.out.println(keyManager.getPublicKey("dante-idp-cert"));
		
		//Test converting SAML Attribute to Element.
		AttributeType attributeType = new AttributeType("urn:oasis:names:tc:SAML:2.0:profiles:attribute:mastercard:card");
		attributeType.addAttributeValue("Test");
		attributeType.setNameFormat(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get());
		Document attributeDocument = SAMLUtil.toSAMLAttributeDocument(attributeType );
		System.out.println(DocumentUtil.getDocumentAsString(attributeDocument));
		
		int keySize = 128;
		
		String encryptedAttributeInCdata = "<![CDATA[<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><xenc:CipherData><xenc:CipherValue>b0XB8fZN/srUYM2efceyROio+cPiFzrzZq3ahf1dOJTmRg0WU/XkdXfW6tf+B++VXXEI1ROL1G9BSsUMjUIhvH+KReFiwDFB5fFBqQdOLqWH7ClmN6IsO4Epzw31GaVXyIa9T46xUyu0rx5r+GNz+1t7j6HEERMeth+WbVcr0x8=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>ZcWMNwpL4hD3RxrWOH6BVy2ZJtbLOkn0EYrYeI1SX2zEj+iAHWk54+vG8yWQhcvG1Mym6MxVfq1Y3U/YdHNVdo6gU7J3rXnLm3Ho7J221xIcJ8WBmudsof9r5Xym3ppHjd3PVPHAQXbs9i97+OlPW/3dM9p248EwYgMn/ZO0yv7iY+9PuyLxUflEKAGj4Fd/giQxNXVx2HcNrTGMNDfFTs1SLOqK4jfRNEiqdsu1GFLTGl1pLV/hbeWI55pVLYensILKRTDRC4XPxfPWT/v0eM9e9yqfNcpw3ko7PFVZ7kZ3KnXmVe18CZ/InDJo04Zzt1lQAXnVGbRMe1uNd3Rk8ErbjYvIr5trzFgt3Bn8lYqpd3RwTiZ+xIH4H0YmwU8ZDdwkGOHec7OX6Sa/kldHSdLrLWhRqK0FlYfoaYlZVHZJolwbZ7uC/jd8T5nMiVcB7/zjOu+cFDefvlwmqdbmRmD51gzJUIyf+S+bPfQ3dax/2hhYcasi+D9PuB02rf1wuaLDC9gPFy2IRCzM4BKT3Tnn/tlHLO5Y54otkNO0YaBzRl7q5je5Pg8leg4LfhqVYBh7Bk0NfIQXyhkJJW/jKJhCVJwtggsPaxsE4xpA5c3phrU2NlEO/a+qKqFkLgye4v6tKONe1LxF/2LCcVEw3s3fZOEgsFnhP36G/DNjJkdZv0iYhxHBWYzRzYF/vbxwcHrvf2jBy/6RvH+NHhOtc/E9DkTdYhCacfLUG+aSAdOh4U/8fieIoCNZOL2evExeCvTXocvg7YOucBg5aQr4iOsxsr1F2/v0+sQGD1Sd45Pyuh2lna4glG2QIUNC495iogPuHIn+65PsoQSEk8l8C4jHhalkuUhL7hNkhY1Zm97GP4FHNTCLxnGsQLhy4XLYwO+/sAWrRkE44aMaODg4LV1isxljpa1j9zF68J/cZL2kvuBgdrtscbKjSZISnM5WXvCfEA994ltMiZ+iVLElPQLU8ZOHUhBYtcYjD404yucSQMvwAt07X5nU0dwpACNhKM9Az0mnI6PepqTX6vHvO8+PqWlA/uCKtWDvkKgxNEr2G5Kxy1MIs1B9Txj6SmTSm1NiesxDvg4EZmIpwjnrNdcddyDCOthKIjewhXZEf2s6XNmKc9APkftzq4G7SYlCBZ93JDYo2b2Zyx+XRGLEIylK3JJRCcaFVFp8tYnmpVu13kch7W/Su+MdXxX03yd1NJDi3fLc+6pAl4ACYhytadaKPAsuhPLmCUq/fkqu0rKvgtRkFbNvacfoV+yc9dfTznO/+hcezIZZ0zNdoE03j1QyVfGt2HM2xDMvQ3E7AsG4gquRF08AwPfIxMTYdhSnBfpTLnbvgLrzRLGkadwK/Q==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>]]></saml:EncryptedAttribute>";
		System.out.println(encryptedAttributeInCdata.replaceAll("<!\\[CDATA\\[(<xenc:EncryptedData.*xenc:EncryptedData>)\\]\\]>", "$1"));
		//Caused by: java.lang.ClassNotFoundException: org.apache.xml.utils.URI$MalformedURIException
//		XMLEncryptionUtil.encryptElement(document, cardElement, keyManager.getPublicKey("dante-idp-cert"), keyManager.getEncryptionKey("all", "AES", keySize), keySize);
//		
//		System.out.println(DocumentUtil.getDocumentAsString(document));
	}

	private static TrustKeyManager getKeyManager() throws TrustKeyConfigurationException, TrustKeyProcessingException {
		KeyProviderType keyProviderType = new KeyProviderType();
		/*
		<KeyProvider ClassName="org.picketlink.identity.federation.core.impl.KeyStoreKeyManager">
		   <Auth Key="KeyStoreURL" Value="/dante_idp_keystore.jks" />
		   <Auth Key="KeyStorePass" Value="MASK-OpPrvagsnxVWPlaosYkKag==" />
		   <Auth Key="SigningKeyPass" Value="MASK-FJ3WVcyw2lcqhvVNmylsvw==" />
		   <Auth Key="SigningKeyAlias" Value="dante-idp-cert" />
		   <Auth Key="salt" Value="71823943" />
		   <Auth Key="iterationCount" Value="27" />
		   <ValidatingAlias Key="localhost" Value="dante-idp-cert"/>
		   <ValidatingAlias Key="127.0.0.1" Value="dante-idp-cert"/>
		</KeyProvider>
		*/
		keyProviderType.setClassName("org.picketlink.identity.federation.core.impl.KeyStoreKeyManager");
		AuthPropertyType authPropertyType = new AuthPropertyType();
		authPropertyType.setKey("KeyStoreURL");
		authPropertyType.setValue("g:\\temp\\dante_idp_keystore.jks");
		keyProviderType.add(authPropertyType);
		
		authPropertyType = new AuthPropertyType();
		authPropertyType.setKey("KeyStorePass");
		authPropertyType.setValue("ksczha0dante");
		keyProviderType.add(authPropertyType);
		
		authPropertyType = new AuthPropertyType();
		authPropertyType.setKey("SigningKeyPass");
		authPropertyType.setValue("skczha0dante");
		keyProviderType.add(authPropertyType);
		
		authPropertyType = new AuthPropertyType();
		authPropertyType.setKey("salt");
		authPropertyType.setValue("71823943");
		keyProviderType.add(authPropertyType);
		
		authPropertyType = new AuthPropertyType();
		authPropertyType.setKey("iterationCount");
		authPropertyType.setValue("27");
		keyProviderType.add(authPropertyType);
		
		TrustKeyManager result = CoreConfigUtil.getTrustKeyManager(keyProviderType );
		result.setAuthProperties(keyProviderType.getAuth());
		
		return result;
	}
}
