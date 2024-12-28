package com.example.movieba.model.response.cv;

import jakarta.persistence.Column;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CvCompanyResponse {
    private long idCv;
    private String nameFile;
}
