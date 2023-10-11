package nlw.tiagosouzac.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nlw.tiagosouzac.todolist.user.IUserRepository;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    var authorization = request.getHeader("Authorization");
    var encodedToken = authorization.substring("Basic".length()).trim();
    byte[] decodedToken = Base64.getDecoder().decode(encodedToken);
    
    String[] credentials = new String(decodedToken).split(":");
    String username = credentials[0];
    String password = credentials[1];

    var user = this.userRepository.findByUsername(username);

    if (user == null) {
      response.sendError(401);
      return;
    }

    var passwordVerifyer = BCrypt.verifyer()
      .verify(password.toCharArray(), user.getPassword());

    if (!passwordVerifyer.verified) {
      response.sendError(401);
      return;
    }

    filterChain.doFilter(request, response);
  }
}
