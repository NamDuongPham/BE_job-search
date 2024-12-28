package com.example.movieba.model.response.cv;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
public class CvResponse {
    private long idCv;
    private String nameFile;
    private String pathFile;
    private Date createTime;
    private String security;
    private String careerName;
    private String locationName;
}
