package com.example.movieba.service.Impl;

import com.example.movieba.entities.Company;
import com.example.movieba.entities.Cv;
import com.example.movieba.entities.News;
import com.example.movieba.entities.User;
import com.example.movieba.exception.BusinessCode;
import com.example.movieba.exception.BusinessException;
import com.example.movieba.mapper.CompanyMapper;
import com.example.movieba.mapper.CvMapper;
import com.example.movieba.mapper.NewsMapper;
import com.example.movieba.model.request.company.CompanyRequest;
import com.example.movieba.model.response.company.CompanyResponse;
import com.example.movieba.model.response.cv.CvResponse;
import com.example.movieba.model.response.news.NewsResponse;
import com.example.movieba.repository.CompanyRepository;
import com.example.movieba.repository.CvRepository;
import com.example.movieba.repository.NewsRepository;
import com.example.movieba.repository.Specification.CompanySpecification;
import com.example.movieba.repository.UserRepository;
import com.example.movieba.service.CompanyService;
import com.example.movieba.service.FileStorageService;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.AllArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class CompanyServiceImpl implements CompanyService {

    private final CompanyRepository companyRepository;
    private final CompanyMapper companyMapper;
    private final UserRepository userRepository;

    private final CvRepository cvRepository;

    private final FileStorageService fileStorageService;

    private final NewsRepository newsRepository;

    private final NewsMapper newsMapper;

    private final CvMapper cvMapper;

    @Override
    public void addInfoCompany(long idUser, CompanyRequest companyRequest) {
        Optional<User> users = userRepository.findById(idUser);
        users.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));

        if (!users.isEmpty()){
            Company company = companyMapper.to(companyRequest);
            company.setUser(users.get());
            companyRepository.save(company);
        }

    }

    @Override
    public CompanyResponse updateCompany(long idUser, long idCompany, CompanyRequest companyRequest) {
        Optional<User> findUsers = userRepository.findById(idUser);
        findUsers.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));

        Optional<Company> findCompany = companyRepository.findByIdCompanyAndUser(idCompany,findUsers.get());
        findCompany.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));

        CompanyResponse companyResponse = new CompanyResponse();


        if (!findCompany.isEmpty()){
            Company company = findCompany.get();
            company.setAddressCompany(companyRequest.getAddressCompany());
            company.setNameCompany(companyRequest.getNameCompany());
            companyRepository.save(company);
            companyResponse = companyMapper.from(company);
            companyResponse.setUserName(findUsers.get().getUserName());
        }


        return companyResponse;
    }

    @Override
    public CompanyResponse getCompanyById(long idCompany) {
        Optional<Company> company = companyRepository.findById(idCompany);
        if (!company.isEmpty()){
            CompanyResponse companyResponse = companyMapper.from(company.get());
            companyResponse.setUserName(company.get().getUser().getUserName());
            return  companyResponse;
        }
        return null;
    }

    @Override
    public CompanyResponse getComByIdNew(long idNew) {
        List<Company> findCom = companyRepository.findAll(new Specification<Company>() {
            @Override
            public Predicate toPredicate(Root<Company> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                Predicate p = criteriaBuilder.conjunction();
                Predicate pFindID = criteriaBuilder.like(root.get("listNews"),"%"+idNew+"%");
                p = criteriaBuilder.and(p,pFindID);
                return p;
            }
        }).stream().filter(t-> {
            String[] arr = t.getListNews().split(",");
            for(String s : arr){
                if (Long.parseLong(s) == idNew){
                    return true;
                }
            }
            return false;
        }).collect(Collectors.toList());
        CompanyResponse companyResponse = companyMapper.from(findCom.get(0));
        companyResponse.setUserName(findCom.get(0).getUser().getUserName());
        return companyResponse;
    }

    @Override
    public List<CompanyResponse> getAllCompany() {
        List<Company> companies = companyRepository.findAll();
        return companies.stream().map(t->{
            CompanyResponse companyResponse = companyMapper.from(t);
            companyResponse.setCountNews(Arrays.stream(t.getListNews().split(",")).filter(d->isNumeric(d)).count());
            companyResponse.setUserName(t.getUser().getUserName());
            return companyResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public List<NewsResponse> getAllNews(long idCom) {
        Optional<Company> findCom = companyRepository.findById(idCom);
        List<Long> ids = Arrays.stream(findCom.get().getListNews().split(",")).map(t-> Long.parseLong(t)).collect(Collectors.toList());
        List<News> listNews = newsRepository.findAllByIdNewIsIn(ids);
        return listNews.stream().map(t->{
            NewsResponse newsResponse = newsMapper.from(t);
            return newsResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public List<NewsResponse> getAllNewsByCom(long idCom) {
        Optional<Company> findCom = companyRepository.findById(idCom);
        List<Long> ids = Arrays.stream(findCom.get().getListNews().split(",")).filter(s->isNumeric(s)).map(t-> Long.parseLong(t)).collect(Collectors.toList());
        List<News> listNews = newsRepository.findAllByIdNewIsIn(ids);
        return listNews.stream().filter(s->s.getStatusNew().compareToIgnoreCase("wait")!=0).map(t->{
            NewsResponse newsResponse = newsMapper.from(t);
            return newsResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public int totalCom() {
        return companyRepository.findAll().size();
    }

    @Override
    public void uploadImageCompany(long idCom, MultipartFile file) {
        Optional<Company> findCom = companyRepository.findById(idCom);
        if (findCom.get()!= null){
            Company company = findCom.get();
            String url = fileStorageService.storeFile(file);
            company.setImageCompany(url);
            companyRepository.save(company);
        }
    }

    @Override
    public List<CompanyResponse> findCom(long idNews) {
        List<Company> companies = companyRepository.findAll(CompanySpecification.filterCom(idNews));
        return companies.stream().filter(t->{
            String[] arr = t.getListNews().split(",");
            List<String> as = Arrays.stream(arr).filter(s->s.equalsIgnoreCase(""+idNews+"")).collect(Collectors.toList());
            if (as.isEmpty()){
                return false;
            }else{
                return true;
            }

        }).map(t->{
            CompanyResponse companyResponse = companyMapper.from(t);
            return companyResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public void addCvFavourite(long idCv, long idCom) {
        Optional<Company> company = companyRepository.findById(idCom);
        if (company.get()!= null){
            String list=",";
            Company companies = company.get();
            if (company.get() != null){
                list+=idCv+",";
            }else{
                list=company.get().getCvFavourite()+idCv+",";
            }
            companies.setCvFavourite(list);
            companyRepository.save(companies);
        }
    }

    @Override
    public List<CvResponse> getCvFavourite(long idCom) {
        Optional<Company> findCom = companyRepository.findById(idCom);
        if (findCom.get() != null){
            return Arrays.stream(findCom.get().getCvFavourite().split(",")).filter(s->!s.isBlank())
                    .map(t->{
                        Optional<Cv> findCv = cvRepository.findById(Long.parseLong(t));
                        CvResponse cvResponse = cvMapper.from(findCv.get());
                        cvResponse.setLocationName(findCv.get().getLocationCv().getNameLocation());
                        cvResponse.setCareerName(findCv.get().getCareerCv().getNameCareer());
                        return cvResponse;
                    }).collect(Collectors.toList());

        }
        return null;
    }

    @Override
    public void deleteCvFavourite(long idCom, long idCv) {
        Optional<Company> findCom = companyRepository.findById(idCom);
        Company update = findCom.get();
        update.setCvFavourite(findCom.get().getCvFavourite().replace(","+idCv,""));
        companyRepository.save(update);
    }

    public static boolean isNumeric(String strNum) {
        if (strNum == null) {
            return false;
        }
        try {
            double d = Double.parseDouble(strNum);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

}
