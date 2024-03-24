package com.example.testsecurityjwt.controller;

import com.example.testsecurityjwt.dto.RequestJoinDTO;
import com.example.testsecurityjwt.service.JoinService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(RequestJoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }

}
