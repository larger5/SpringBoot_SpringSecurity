package com.cun.security3.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class testController {

    @GetMapping("index")
    public String index(){
        return "Hello";
    }
}
