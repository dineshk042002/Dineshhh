import axios from 'axios';
const API = axios.create({baseURL : `http://localhost:5500/`})
//const API = axios.create({baseURL : `https://dineshkk.onrender.com/`})
API.interceptors.request.use(req=>{
    if(localStorage.getItem('Profile')){
        req.headers.authorization =  `Bearer ${JSON.parse(localStorage.getItem('Profile')).token}`

    }
    return req;
});
export const login=(authData)=>API.post('/user/login',authData);
export const updateChanelData=(id,updateData)=>API.patch(`/user/update/${id}`,updateData);
export const fetchAllChanel=()=>API.get('/user/getAllChanels');

export const uploadVideo=(fileData,fileOptions)=> API.post('/video/uploadVideo',fileData, fileOptions);
export const getVideos=()=>API.get('/video/getvideos');
export const likeVideo=(id,Like)=>API.patch(`/video/like/${id}`,{Like});
export const viewsVideo=(id)=>API.patch(`/video/view/${id}`);

export const addToLikedVideo=(likeVideoData)=>API.post('/video/likeVideo',likeVideoData);
export const getAlllikedVideo=()=>API.get('/video/getAlllikeVideo');
export const deletelikedVideo=(videoId,Viewer)=>API.delete(`/video/deleteLikedVideo/${videoId}/${Viewer}`)

export const addTowatchLater=(watchLaterData)=>API.post('/video/watchLater',watchLaterData);
export const getAllwatchLater=()=>API.get('/video/getAllwatchLater');
export const deleteWatchLater=(videoId,Viewer)=>API.delete(`/video/deleteWatchlater/${videoId}/${Viewer}`)

export const addToHistroy=(HistroyData)=>API.post('/video/Histroy',HistroyData);
export const getAllHistroy=()=>API.get('/video/getAllHistroy');
export const deleteHistroy=(userId)=>API.delete(`/video/deleteHistroy/${userId}`);

export const postComment=(CommentData)=> API.post('/comment/post',CommentData)
export const deleteComment=(id)=> API.delete(`/comment/delete/${id}`)
export const editComment=(id,commentBody)=> API.patch(`/comment/edit/${id}`,{commentBody})
export const getAllComment=()=> API.get('/comment/get')