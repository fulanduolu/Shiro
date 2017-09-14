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
		//1.��ȡshiro��subject
		Subject currentUser = SecurityUtils.getSubject();
		//2.�ж��Ƿ���֤����
		if(!currentUser.isAuthenticated()){
			//��ʾû����֤��,���û����������װΪToken����
			UsernamePasswordToken token = new UsernamePasswordToken(username,password);
			//��ס��
			token.setRememberMe(true);
			
			try{
				currentUser.login(token);
			}catch(AuthenticationException e){
				//��¼��֤ʱ�����쳣
				System.out.println("=====>��¼ʧ��"+e.getMessage());
			}
		}
		
		//��¼�ɹ���ת��
		return "redirect:/list.jsp";
	}
	
}
