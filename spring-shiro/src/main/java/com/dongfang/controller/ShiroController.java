package com.dongfang.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.dongfang.service.ShiroService;

@Controller
public class ShiroController {
	
	@Autowired
	private ShiroService shiroService;

	@RequestMapping("/testShiroAnnotation")
	public String testShiroAnnotation(){
		shiroService.testMethod();
		return "redirect:/list.jsp";
	}
	
	@RequestMapping("/ShiroLogin")
	public String login(@RequestParam("username") String username, @RequestParam("password") String password) {
		//1.获取shiro的subject
		Subject currentUser = SecurityUtils.getSubject();
		//2.判断是否验证过了
		if(!currentUser.isAuthenticated()){
			//表示没有验证过,将用户名与密码封装为Token序列
			UsernamePasswordToken token = new UsernamePasswordToken(username,password);
			//记住我
			token.setRememberMe(true);
			
			try{
				currentUser.login(token);
			}catch(AuthenticationException e){
				//登录认证时出现异常
				System.out.println("=====>登录失败"+e.getMessage());
			}
		}
		
		//登录成功跳转的
		return "redirect:/list.jsp";
	}
	
}
