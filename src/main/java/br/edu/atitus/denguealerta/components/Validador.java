package br.edu.atitus.denguealerta.components;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Validador {

    private static final String EMAIL_REGEX =
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$";

    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    public static boolean ValidaEmail(String email) {
        if (email == null) {
            return false;
        }

        Matcher matcher = EMAIL_PATTERN.matcher(email);
        return matcher.matches();
    }

    public static boolean validaCPF(String cpf) {
        // Remove caracteres não numéricos
        cpf = cpf.replaceAll("[^\\d]", "");

        // Verifica se o CPF tem 11 dígitos
        if (cpf.length() != 11) {
            return false;
        }

        // Verifica se todos os dígitos são iguais, por exemplo "11111111111"
        if (cpf.matches("(\\d)\\1{10}")) {
            return false;
        }

        try {
            // Calcula o primeiro dígito verificador
            int sum = 0;
            for (int i = 0; i < 9; i++) {
                sum += (cpf.charAt(i) - '0') * (10 - i);
            }
            int firstCheckDigit = 11 - (sum % 11);
            if (firstCheckDigit == 10 || firstCheckDigit == 11) {
                firstCheckDigit = 0;
            }

            // Verifica o primeiro dígito verificador
            if (firstCheckDigit != (cpf.charAt(9) - '0')) {
                return false;
            }

            // Calcula o segundo dígito verificador
            sum = 0;
            for (int i = 0; i < 10; i++) {
                sum += (cpf.charAt(i) - '0') * (11 - i);
            }
            int secondCheckDigit = 11 - (sum % 11);
            if (secondCheckDigit == 10 || secondCheckDigit == 11) {
                secondCheckDigit = 0;
            }

            // Verifica o segundo dígito verificador
            return secondCheckDigit == (cpf.charAt(10) - '0');
        } catch (NumberFormatException e) {
            return false;
        }
    }

}