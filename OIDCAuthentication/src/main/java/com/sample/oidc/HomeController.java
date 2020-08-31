package com.sample.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @RequestMapping("/home")
    @ResponseBody
    public final String home() {
        OpenIdConnectUserDetails principal = (OpenIdConnectUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        logger.info(principal.getUserId());
        return "Welcome, " + principal.getUserInfo();
    }
    
    @RequestMapping("/home1")
    @ResponseBody
    public final String home1() {
        OpenIdConnectUserDetails principal = (OpenIdConnectUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        logger.info(principal.getUserId());
        return "Welcome, " + principal.getUserId();
    }
  
    @RequestMapping("/home2")
    @ResponseBody
    public final String home2() {
        OpenIdConnectUserDetails principal = (OpenIdConnectUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        logger.info(principal.getUserId());
        return "Welcome, " + principal.getUserId();
    }
  
   
}