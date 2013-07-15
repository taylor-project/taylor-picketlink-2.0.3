package org.picketlink.identity.federation.core.saml.v2.holders;

/**
 * Holds SAML Attribute that needs to be returned.
 * 
 * @author Charles Zhao
 *
 */
public class AttributeHolder {
	private boolean encryptedRequired;
	private String attributeName;
	private Object attributeValue; //Can be a String, Element (represents well formed xml data).

	public AttributeHolder(String attributeName, Object attributeValue) {
		this.attributeName = attributeName;
		this.attributeValue = attributeValue;
	}
	
	public AttributeHolder(boolean encryptedRequired, String attributeName,
			Object attributeValue) {
		this.encryptedRequired = encryptedRequired;
		this.attributeName = attributeName;
		this.attributeValue = attributeValue;
	}

	public boolean isEncryptedRequired() {
		return encryptedRequired;
	}
	public void setEncryptedRequired(boolean encryptedRequired) {
		this.encryptedRequired = encryptedRequired;
	}
	public Object getAttributeValue() {
		return attributeValue;
	}
	public void setAttributeValue(Object attributeValue) {
		this.attributeValue = attributeValue;
	}
	public String getAttributeName() {
		return attributeName;
	}
	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
	}
}
