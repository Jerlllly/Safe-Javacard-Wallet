package Wallet;

import javacard.security.*;
import javacardx.crypto.*;

public class InternalAuthentication {

	  private DESKey deskey;
	  Cipher  CipherObj;
	  short flag=0x00;
	  //单重DES密钥
	  private byte[] keyData = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
	  
	protected InternalAuthentication() {
		
		  //生成密钥对象
	      deskey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
							
	      //生成加密对象
	      CipherObj   = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
	      
		  	}
	public void doAuthentication(byte [] buffer) {
			
						
	      //设置ＤＥＳ密钥					
	      deskey.setKey(keyData, (short)0);
	      
	      //初始化密钥及加密模式
	      CipherObj.init(deskey, Cipher.MODE_ENCRYPT);
	      
	       //加密
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