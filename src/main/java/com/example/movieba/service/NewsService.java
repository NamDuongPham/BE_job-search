package com.example.movieba.service;


import com.example.movieba.model.request.news.NewsRequest;
import com.example.movieba.model.response.news.NewsResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;


import java.util.List;

public interface NewsService {
    void addNew(long idCom, NewsRequest newsRequest);
    void updateNew(long idNew, NewsRequest newsRequest);

    void acceptNew(long idNew, String status);

    NewsResponse getNews(long idNew);

    List<NewsResponse> getAllNews();

    List<NewsResponse> filterNews();

    int total();

    List<NewsResponse> getAllNewsByIds(long idCom);

    Page<NewsResponse> getNewLimit(Pageable pageable);


    int totalFindNews();

    void applyJob(long idCv, long idNew, HttpServletRequest request);

    NewsResponse getAllNewsByIdUser(long idUser);

    List<NewsResponse> findAllByKeyWord(String title, Long locationId, Long careerId,
                                String skill, String des, String localName, String level, Integer sort );

}
