package br.edu.atitus.denguealerta.controllers;

import br.edu.atitus.denguealerta.components.JwtUtils;
import br.edu.atitus.denguealerta.dtos.SigninDTO;
import br.edu.atitus.denguealerta.dtos.SignupDTO;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.web.bind.annotation.*;

import br.edu.atitus.denguealerta.components.TipoUsuario;
import br.edu.atitus.denguealerta.entities.UsuarioEntity;
import br.edu.atitus.denguealerta.services.UsuarioService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final AuthenticationConfiguration auth;

    public AuthController(UsuarioService usuarioService, AuthenticationConfiguration auth) {
        super();
        this.usuarioService = usuarioService;
        this.auth = auth;
    }

    @PostMapping("/signin")
    public ResponseEntity<String> signin(@RequestBody SigninDTO signinDTO) throws Exception {
            auth.getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(signinDTO.getEmail(), signinDTO.getSenha()));
        String jwtToken = JwtUtils.generateTokenFromUsername(signinDTO.getEmail());
            return  ResponseEntity.ok(jwtToken);
    }

    @PostMapping("/signup")
    public ResponseEntity<UsuarioEntity> signup(@RequestBody SignupDTO signupDTO) throws Exception {
        UsuarioEntity novoUsuario = new UsuarioEntity();
        BeanUtils.copyProperties(signupDTO, novoUsuario);
        novoUsuario.setTipo(TipoUsuario.Cidadao);

        usuarioService.save(novoUsuario);

        return ResponseEntity.status(HttpStatus.CREATED).body(novoUsuario);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> trataExceptions(Exception e) {
        String cleanMessage = e.getMessage().replaceAll("\\r\\n", "");
        return ResponseEntity.badRequest().body(cleanMessage);
    }

}