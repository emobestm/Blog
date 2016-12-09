package softuniBlog.controller;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import softuniBlog.bindingModel.FileBindingModel;
import softuniBlog.bindingModel.UserBindingModel;
import softuniBlog.entity.Role;
import softuniBlog.entity.User;
import softuniBlog.repository.RoleRepository;
import softuniBlog.repository.UserRepository;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.util.List;

@Controller
public class UserController {

    @Autowired
    RoleRepository roleRepository;
    @Autowired
    UserRepository userRepository;



    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("view", "user/register");

        return "base-layout";
    }

    @PostMapping("/register")
    public String registerProcess(UserBindingModel userBindingModel) {

        if (!userBindingModel.getPassword().equals(userBindingModel.getConfirmPassword())) {
            return "redirect:/register";
        }


        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        User user = new User(
                userBindingModel.getEmail(),
                userBindingModel.getFullName(),
                bCryptPasswordEncoder.encode(userBindingModel.getPassword())
        );

        Role userRole = this.roleRepository.findByName("ROLE_USER");

        user.addRole(userRole);

        this.userRepository.saveAndFlush(user);

        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("view", "user/login");

        return "base-layout";
    }

    @GetMapping("/about")
    public String about(Model model) {
        model.addAttribute("view", "user/about");

        return "base-layout";
    }
    @GetMapping("/contact")
    public String contact(Model model) {
        model.addAttribute("view", "user/contact");

        return "base-layout";
    }
    @GetMapping("/photo")
    public String photo(Model model) {
        model.addAttribute("view", "user/photo");


        return "base-layout";
    }
    @GetMapping("/video")
    public String video(Model model) {
        model.addAttribute("view", "user/video");


        return "base-layout";
    }



    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logoutPage(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }

        return "redirect:/login?logout";
    }

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public String profilePage(Model model) {
        UserDetails principal = (UserDetails) SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();

        User user = this.userRepository.findByEmail(principal.getUsername());

        model.addAttribute("user", user);
        model.addAttribute("view", "user/profile");

        return "base-layout";
    }
    @GetMapping("/file/upload")
    public String file (Model model){
        model.addAttribute("view","file/upload");

        return "base-layout";

    }
    @PostMapping("/file/upload")
    public String UploadFile (FileBindingModel fileBindingModel,
                              HttpServletRequest servletRequest){


        MultipartFile file = fileBindingModel.getPicture();
        if (file!=null){

            String originalFileName = file.getOriginalFilename();
            File imageFile = new File("C:\\Users\\Emil\\Desktop\\Git\\blog1\\blog\\src\\main\\resources\\images", originalFileName);
            String status = "Success";
            System.out.println("File" +originalFileName+" has been added successfully");

            try {
                file.transferTo(imageFile);
             //article.setImagePath(imageFile.getPath());
           } catch (IOException e){
                e.printStackTrace();
                status="Fail";
            }
        }
        return "redirect:/";
    }





}





