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
		
		//1.将token  转换成UsernamePasswordToken   ,因为是那边传过来的，肯定是这个类型。
		UsernamePasswordToken upToken=(UsernamePasswordToken)token;
		//2.从UsernamePasswordToken中获取username。
		String username = upToken.getUsername();
		//3.调用数据库中的方法查询username对应的用户记录。
		System.out.println("从数据库中获取username："+username+"所对应的用户信息");
		
		//4.若用户不存在，则可以抛出UnkownAccountException 异常。
		if("unknown".equals(username)){
			throw new UnknownAccountException("用户不存在");
		}
		//5.根据用户信息的情况决定是否需要抛出其他的异常。
		if("moster".equals(username)){
			throw new LockedAccountException("用户被锁定");
		}
		//6.根据用户的情况来构建AuthenticationInfo对象，并返回。通常使用的实现类为:SimpleAuthenticationInfo
		//以下信息是从数据库中获取的。
		//1).principal:认证的实体信息,可以是username也可以是数据表对应的实体信息
		Object principal = username;
		//2).credentials:密码
		Object credentials = null;    //"fc1709d0a95a6be30bc5926fdb7f22f4";
		if("admin".equals(username)){
			credentials = "ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
		}else if("user".equals(username)){
			credentials = "073d4c3ae812935f23cb3f2a71943f49e082a718";
		}
		//3).realmName：当前realm对象的name，调用父类的getName()方法即可。
		String realmName = getName();
		//4).credentialsSalt：为加密算法加盐。
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		SimpleAuthenticationInfo info=null;//new SimpleAuthenticationInfo(principal,credentials,realName);
		info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
		return info;
	}

	public static void main(String[] args) {
		//加密算法
		String hashAlgorithmName ="SHA1";
		//原来密码
		Object password = "123456";
		//延值
		Object salt=ByteSource.Util.bytes("admin");
		//加密次数
		int hashIterations = 1024;
		Object result = new SimpleHash(hashAlgorithmName,password,salt,hashIterations);
		System.out.println(result);
	}	

}
