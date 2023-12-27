import React, { useState } from "react";
import './VideoUpload.css'
import { useDispatch, useSelector } from "react-redux";
import { uploadVideo } from "../../actions/video";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar"

function VideoUpload({ setVideoUploadPage }) {
    const CurrentUser = useSelector(state => state.currentUserReducer)
    const dispatch = useDispatch();
    const [title, setTitle] = useState("");
    const [videoFile, setVideoFile] = useState("");

    const handleSetVideoFile = (e) => {
        setVideoFile(e.target.files[0]);
    }

    const [progress, setProgress] = useState(0);

    const fileOptions = {
        onUploadProgress: (ProgressEvent) => {
            const { loaded, total } = ProgressEvent;
            const percentage = Math.floor(((loaded / 1000) * 100) / (total / 1000));
            setProgress(percentage)
            if (percentage === 100) {
                setTimeout(function () { }, 3000);
                setVideoUploadPage(false);
            }
        }
    }

    const uploadVideoFile = () => {
        if (!title) {
            alert("Please Enter a Title of the Video");
        } else if (!videoFile) {
            alert("Please Attach a Video File");
        } else if (videoFile.size > 1000000) {
            alert("Please attach a video less than 10000 bytes");
        } else {
            const fileData = new FormData();
            fileData.append("file", videoFile);
            fileData.append("title", title);
            fileData.append("chanel", CurrentUser?.result._id);
            fileData.append("Uploader", CurrentUser?.result.name);

            dispatch(
                uploadVideo({
                    fileData: fileData,
                    fileOptions: fileOptions
                })
            );
        }
    };

    return (
        <div className="container_VidUpload">
            <input
                type="submit"
                name="date"
                value={"x"}
                onClick={() => setVideoUploadPage(false)}
                className="ibtn_x" />
            <div className="container2_VidUpload">
                <div className="ibox_div_vidupload">
                    <input type="text"
                        onChange={(e) => { setTitle(e.target.value) }}
                        className="ibox_vidupload"
                        maxLength={30}
                        placeholder="Enter Title of your video" />

                    <label htmlFor="file" className="ibox_vidupload btn_vidupload">
                        <input type="file"
                            name="file"
                            className="ibox_vidupload"
                            style={{ fontSize: "1rem" }}
                            onChange={(e) => { handleSetVideoFile(e) }} />
                    </label>
                </div>
                <div className="ibox_div_vidupload">
                    <input type="submit" onClick={() => uploadVideoFile()} value="Upload"
                        className="ibox_vidupload btn_vidupload"
                    />
                </div>
                <div className="loader ibox_div_vidupload">
                    <CircularProgressbar
                        value={progress}
                        text={`${progress}`}
                        styles={
                            buildStyles({
                                rotation: 0.25,
                                strokeLinecap: 'butt',
                                textSize: "20px",
                                pathTransitionDuration: 0.5,
                                pathColor: `rgba(255,255,255,${progress / 100})`,
                                textColor: "#f88",
                                trailColor: "#adff2f",
                                backgroundColor: "#3e98c7"
                            })
                        }
                    />
                </div>
            </div>
        </div>
    )
}

export default VideoUpload;
