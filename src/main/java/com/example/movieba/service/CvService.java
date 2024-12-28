package com.example.movieba.service;

import com.example.movieba.entities.Cv;
import com.example.movieba.model.response.cv.CvInNewResponse;
import com.example.movieba.model.response.cv.CvRequest;
import com.example.movieba.model.response.cv.CvResponse;
import com.example.movieba.model.response.news.NewHasCvResponse;

import java.util.List;

public interface CvService {
    int getTotalCvs();

    List<Cv> getAllCvs();

    List<CvInNewResponse> getByCvsByIdNew(long idNew);

    void changeActionCv(long idNew, long idCv, String status, String content);

    String addCv(long userId, CvRequest cvRequest);

    void changeSecurity(long idCv, String security);

    List<CvResponse> findCvs(String nameCv, Long careerId, Long locationId);

    List<CvResponse> findCvsPublic();


    List<NewHasCvResponse> myListCv(Long idUser);

    void deleteCv(Long idUser, Long idCv);

}
