package Wallet;

import javacard.security.*;
import javacardx.crypto.*;

public class InternalAuthentication {

	  private DESKey deskey;
	  Cipher  CipherObj;
	  short flag=0x00;
	  //����DES��Կ
	  private byte[] keyData = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	  
	protected InternalAuthentication() {
		
		  //������Կ����
	      deskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
							
	      //���ɼ��ܶ���
	      CipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	      
		  	}
	public void doAuthentication(byte [] buffer) {
			
						
	      //���ãģţ���Կ					
	      deskey.setKey(keyData, (short)0);
	      
	      //��ʼ����Կ������ģʽ
	      CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
	      
	       //����
	       CipherObj.doFinal(buffer, (short)5, (short)8, buffer, (short)0); 

	}
	public void ChangeFlag() 
	{
		flag=0x01;
	}
	public short getFlag()
	{
		short result=flag;
		return result;
	}
}