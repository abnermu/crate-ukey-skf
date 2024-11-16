# 判断是否已将原始的远程仓库名origin重命名为github
function Is-Origin-Renamed {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "github") {
            return $true
        }
    }
    return $false
}

# 判断是否已添加gitlab远程仓库
function Is-Gitlab-Added {
    $remotev = git remote -v
    $remotevarr = $remotev -split '\s+'
    for ($i = 0; $i -lt $remotevarr.Length; $i += 3) {
        if ($remotevarr[$i] -eq "gitlab") {
            return $true
        }
    }
    return $false;
}

$renamed = Is-Origin-Renamed
if ($renamed) {
    Write-Host "github远程仓库已重命名，无须再次操作。"
}
else {
    git remote rename origin github
    Write-Host "github远程仓库（origin）已重命名为github。"
}

$gitlabadded = Is-Gitlab-Added
if ($gitlabadded) {
    Write-Host "当前github仓库已与公司内部gitlab仓库关联完成，无须再次操作。"
}
else {
    git remote add gitlab http://gitlab.lnwlzb.com/jy/jy-crates/crate-ukey-skf.git
    git push -u gitlab main
    Write-Host "github远程仓库已关联到公司内部gitlab并进行了初始化push。"
}

# 执行外部命令，实际上是起了个命令行去跑命令，但这里边不需要这么做
# $process = Start-Process "git" -ArgumentList "remote", "-v" -PassThru
# $process.WaitForExit()
# Write-Host "git remote -v 命令执行结束"