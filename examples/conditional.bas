Option Explicit

#If VBA7 Then
Public Sub ConfigureForVBA7()
    Dim pointerSize As LongPtr
End Sub
#Else
Public Sub ConfigureForLegacyVBA()
    Dim pointerSize As Long
End Sub
#End If
