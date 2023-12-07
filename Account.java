public class Account {
    private String userId;
    private double savingsBalance;
    private double checkingBalance;

    public Account(String userId, double savingsBalance, double checkingBalance) {
        this.userId = userId;
        this.savingsBalance = savingsBalance;
        this.checkingBalance = checkingBalance;
    }

    public String getUserId() {
        return userId;
    }

    public double getSavingsBalance() {
        return savingsBalance;
    }

    public double getCheckingBalance() {
        return checkingBalance;
    }

    public void setSavingsBalance(double savingsBalance) {
        this.savingsBalance = savingsBalance;
    }

    public void setCheckingBalance(double checkingBalance) {
        this.checkingBalance = checkingBalance;
    }
}
