package jenty.jensen.spring_cognito_oauth.controllers;

import jakarta.servlet.http.HttpSession;
import jenty.jensen.spring_cognito_oauth.configurations.SecurityConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String getHomePage(Authentication auth, Model model) {
        //Authentication = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) {
            model.addAttribute("loggedIn", false);
        } else {
            var username = auth.getName();

            model.addAttribute("loggedIn", true);
            model.addAttribute("username", username);

        }
        return "home";

    }
    @PostMapping("/delete")
    public String deleteUser(Authentication auth, HttpSession session ) {
        var username = auth.getName();

        if (auth.getName().equals(username)) {
            SecurityConfiguration.deleteUser(username);

            session.invalidate();
            return "redirect:/";

        }
        return "error";
    }

}
