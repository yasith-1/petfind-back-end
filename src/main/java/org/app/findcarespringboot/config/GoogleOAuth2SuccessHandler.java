package org.app.findcarespringboot.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.app.findcarespringboot.util.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class GoogleOAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;

    // Spring invoke this when if login success
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        //authentication --> contains the logged-in user's info.
        //oAuth2User --> represents the Google user.
        //getAttribute("email") --> gets the user's email address from their Google profile.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        // Generate JWT
        String token = jwtUtil.generateToken(email, 60 * 60 * 24 * 7);

        response.sendRedirect("http://localhost:5500/pages/homePage.html?token=" + token);
    }
}

