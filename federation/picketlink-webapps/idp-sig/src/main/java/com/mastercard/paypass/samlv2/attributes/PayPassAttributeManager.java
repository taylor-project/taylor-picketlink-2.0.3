package com.mastercard.paypass.samlv2.attributes;

import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.picketlink.identity.federation.core.interfaces.AttributeManager;
import org.picketlink.identity.federation.core.saml.v2.holders.AttributeHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * @author Charles Zhao
 */
public class PayPassAttributeManager implements AttributeManager {
	private static Log log = LogFactory.getLog(PayPassAttributeManager.class);
	
	public static final String CARD_ATTRIBUTE_URI_NAME = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:mastercard:card";
	public static final String BILLING_ADDRESS_ATTRIBUTE_URI_NAME = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:mastercard:billing-address";
	public static final String CONTACT_ATTRIBUTE_URI_NAME = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:mastercard:contact";
	public static final String SHIPPING_ADDRESS_ATTRIBUTE_URI_NAME = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:mastercard:shipping-address";
	
	public Map<String, Object> getAttributes(Principal userPrincipal,
			List<String> attributeKeys) {
		Map<String, Object> attributes = new HashMap<String, Object>();

		boolean cardAttributeRequested = attributeKeys.contains(CARD_ATTRIBUTE_URI_NAME);
		boolean billingAddressAttributeRequested = attributeKeys.contains(BILLING_ADDRESS_ATTRIBUTE_URI_NAME);
		boolean shippingAddressAttributeRequested = attributeKeys.contains(SHIPPING_ADDRESS_ATTRIBUTE_URI_NAME);
		boolean contactAttributeRequested = attributeKeys.contains(CONTACT_ATTRIBUTE_URI_NAME);
		
		log.info("Loading account details for user: " + userPrincipal.getName());
		
		if ( !cardAttributeRequested && !contactAttributeRequested && !billingAddressAttributeRequested & !shippingAddressAttributeRequested) {
			return attributes;
		}
			
		try {
			InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(userPrincipal.getName() + ".xml");
			if ( is == null ) {
				log.warn("Unable to find account details for user: " + userPrincipal.getName());
				return attributes;
			}
			
			Document document = DocumentUtil.getDocument(is);
			if ( cardAttributeRequested ) {
				addAttribute(document, attributes, "Card", CARD_ATTRIBUTE_URI_NAME, true);
			}
			
			if ( contactAttributeRequested ) {
				addAttribute(document, attributes, "Contact", CONTACT_ATTRIBUTE_URI_NAME, false);
			}
			
			if ( billingAddressAttributeRequested ) {
				addAttribute(document, attributes, "BillingAddress", BILLING_ADDRESS_ATTRIBUTE_URI_NAME, false);
			}
			
			if ( shippingAddressAttributeRequested ) {
				addAttribute(document, attributes, "ShippingAddress", SHIPPING_ADDRESS_ATTRIBUTE_URI_NAME, false);
			}
			
		} catch (Exception e) {
			log.warn("Unable to load account details for user: " + userPrincipal.getName());
		}
		return attributes;
	}
	
	private void addAttribute(Document document, Map<String, Object> attributes, String elementName, String elementUriName, boolean encryptionRequired) {
		NodeList elementList = document.getElementsByTagName(elementName);
		List<Object> attributeValue = new ArrayList<Object>();
		for ( int i = 0; i < elementList.getLength(); i++ ) {
			Element element = (Element)elementList.item(i);
			attributeValue.add(element); //pass as xml
			//attributeValue.add(DocumentUtil.getNodeAsString(element).replaceAll("\\r|\\n|\\t", "")); //pass as a string
		}
		attributes.put(elementUriName, new AttributeHolder(encryptionRequired, elementUriName, attributeValue));
	}
}
