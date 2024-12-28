package com.example.movieba.service;


import com.example.movieba.model.request.company.CompanyRequest;
import com.example.movieba.model.response.company.CompanyResponse;
import com.example.movieba.model.response.cv.CvResponse;
import com.example.movieba.model.response.news.NewsResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface CompanyService {

    void addInfoCompany(long idUser, CompanyRequest companyRequest);

    CompanyResponse updateCompany(long idUser, long idCompany, CompanyRequest companyRequest);

    CompanyResponse getCompanyById(long idCompany);

    CompanyResponse getComByIdNew(long idNew);

    List<CompanyResponse> getAllCompany();

    List<NewsResponse> getAllNews( long idCom);

    List<NewsResponse> getAllNewsByCom(long idCom);

    int totalCom();

    void uploadImageCompany(long idCom, MultipartFile file);

    List<CompanyResponse> findCom(long idNews);

    void addCvFavourite(long idCv, long idCom);

    List<CvResponse> getCvFavourite(long idCom);

    void deleteCvFavourite(long idCom,long idCv);


}
