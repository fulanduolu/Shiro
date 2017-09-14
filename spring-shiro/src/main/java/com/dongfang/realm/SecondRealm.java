package com.dongfang.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.ByteSource;

public class SecondRealm extends AuthenticatingRealm {

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		System.out.println("[SecondRealm] doGetAuthenticationInfo");
		
		//1.��token  ת����UsernamePasswordToken   ,��Ϊ���Ǳߴ������ģ��϶���������͡�
		UsernamePasswordToken upToken=(UsernamePasswordToken)token;
		//2.��UsernamePasswordToken�л�ȡusername��
		String username = upToken.getUsername();
		//3.�������ݿ��еķ�����ѯusername��Ӧ���û���¼��
		System.out.println("�����ݿ��л�ȡusername��"+username+"����Ӧ���û���Ϣ");
		
		//4.���û������ڣ�������׳�UnkownAccountException �쳣��
		if("unknown".equals(username)){
			throw new UnknownAccountException("�û�������");
		}
		//5.�����û���Ϣ����������Ƿ���Ҫ�׳��������쳣��
		if("moster".equals(username)){
			throw new LockedAccountException("�û�������");
		}
		//6.�����û������������AuthenticationInfo���󣬲����ء�ͨ��ʹ�õ�ʵ����Ϊ:SimpleAuthenticationInfo
		//������Ϣ�Ǵ����ݿ��л�ȡ�ġ�
		//1).principal:��֤��ʵ����Ϣ,������usernameҲ���������ݱ��Ӧ��ʵ����Ϣ
		Object principal = username;
		//2).credentials:����
		Object credentials = null;    //"fc1709d0a95a6be30bc5926fdb7f22f4";
		if("admin".equals(username)){
			credentials = "ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
		}else if("user".equals(username)){
			credentials = "073d4c3ae812935f23cb3f2a71943f49e082a718";
		}
		//3).realmName����ǰrealm�����name�����ø����getName()�������ɡ�
		String realmName = getName();
		//4).credentialsSalt��Ϊ�����㷨���Ρ�
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		SimpleAuthenticationInfo info=null;//new SimpleAuthenticationInfo(principal,credentials,realName);
		info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
		return info;
	}

	public static void main(String[] args) {
		//�����㷨
		String hashAlgorithmName ="SHA1";
		//ԭ������
		Object password = "123456";
		//��ֵ
		Object salt=ByteSource.Util.bytes("admin");
		//���ܴ���
		int hashIterations = 1024;
		Object result = new SimpleHash(hashAlgorithmName,password,salt,hashIterations);
		System.out.println(result);
	}	

}
